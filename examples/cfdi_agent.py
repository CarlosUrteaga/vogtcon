# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Offline CFDI consumer: deterministic facts, typed agent, governed local ledger.

Synthetic integration example, NOT a SAT validator. A date/amount match is only
a candidate under this application's policy. One process owns each ledger.
Run ``python examples/cfdi_agent.py --output-dir /tmp/cfdi-demo`` after installing
the consumer requirements. No remote model, tax credentials or network needed.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import nullcontext
import csv
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Literal
from uuid import UUID, uuid4

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException
from pydantic import BaseModel, ConfigDict, Field
from pydantic_ai import Agent, ModelResponse, ModelRetry, RunContext, ToolCallPart
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.usage import UsageLimits

from vogtcon import (
    ActionProposal, EnforcementPolicy, ExecutionContext, GovernorInput,
    JsonlDecisionLog, RuleCatalog, TelemetryObserver, WorkflowController,
)

FIXTURES = Path(__file__).with_name("cfdi_fixtures")
CATALOG_PATH = FIXTURES / "catalog.json"
CONTRACT_PATH = Path(__file__).with_name("cfdi_contract.yaml")
CFDI = "{http://www.sat.gob.mx/cfd/4}"
TIMBRE = "{http://www.sat.gob.mx/TimbreFiscalDigital}TimbreFiscalDigital"
RFC = re.compile(r"[A-ZÑ&]{3,4}[0-9]{6}[A-Z0-9]{3}")


class InputError(ValueError):
    """Invalid host input; messages intentionally exclude private source data."""


class FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Profile(FrozenModel):
    receiver_rfc: str
    person_type: Literal["fisica", "moral"]
    fiscal_regime: str


class Invoice(FrozenModel):
    invoice_uuid: str
    issuer_rfc: str
    receiver_rfc: str
    fiscal_regime: str
    use: str
    issued_on: date
    total: Decimal
    kind: str
    currency: str
    method: str
    unsupported_structure: bool


class BankTransaction(FrozenModel):
    transaction_id: str = Field(min_length=1, max_length=128)
    date: date
    amount_mxn: Decimal


class Finding(FrozenModel):
    invoice_uuid: str
    status: Literal["matched", "mismatch", "ambiguous", "needs_review"]
    reason_code: str
    bank_transaction_id: str | None
    evidence_ids: list[str]


class ReconciliationReport(FrozenModel):
    items: list[Finding]


class LedgerRow(FrozenModel):
    invoice_uuid: str
    bank_transaction_id: str
    run_id: str
    authorized_by_host: bool


def money(raw: str) -> Decimal:
    """Accept finite decimal amounts with at most two fractional digits."""
    if not isinstance(raw, str) or not re.fullmatch(r"-?[0-9]+(?:\.[0-9]{1,2})?", raw):
        raise InputError("invalid monetary amount")
    try:
        return Decimal(raw)
    except InvalidOperation:
        raise InputError("invalid monetary amount") from None


def parse_invoice(path: Path) -> Invoice:
    """Extract a minimal CFDI 4.0 view; reject DTDs and XML entities."""
    try:
        with path.open("rb") as source:
            raw = source.read(2_000_001)
        if len(raw) > 2_000_000:
            raise InputError("XML size limit exceeded")
        root = ElementTree.fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        if root.tag != CFDI + "Comprobante" or root.attrib.get("Version") != "4.0":
            raise InputError("expected CFDI namespace and version 4.0")
        def one(tag):
            found = root.findall(tag)
            if len(found) != 1:
                raise InputError("missing or duplicate XML node")
            return found[0]
        sender, receiver = one(CFDI + "Emisor"), one(CFDI + "Receptor")
        complement = one(CFDI + "Complemento")
        stamps = complement.findall(TIMBRE)
        if len(stamps) != 1:
            raise InputError("missing or duplicate invoice UUID")
        for rfc in (sender.attrib["Rfc"], receiver.attrib["Rfc"]):
            if not RFC.fullmatch(rfc):
                raise InputError("invalid RFC syntax")
        timestamp = root.attrib["Fecha"]
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", timestamp):
            raise InputError("expected local CFDI timestamp without timezone")
        total = money(root.attrib["Total"])
        if total <= 0:
            raise InputError("expected positive invoice total")
        unsupported = (
            any(child.tag != TIMBRE for child in complement)
            or root.find(".//" + CFDI + "Retenciones") is not None
            or root.find(CFDI + "CfdiRelacionados") is not None
        )
        return Invoice(
            invoice_uuid=str(UUID(stamps[0].attrib["UUID"])),
            issuer_rfc=sender.attrib["Rfc"], receiver_rfc=receiver.attrib["Rfc"],
            fiscal_regime=receiver.attrib["RegimenFiscalReceptor"], use=receiver.attrib["UsoCFDI"],
            issued_on=datetime.fromisoformat(timestamp).date(), total=total,
            kind=root.attrib["TipoDeComprobante"], currency=root.attrib["Moneda"],
            method=root.attrib.get("MetodoPago", ""), unsupported_structure=unsupported,
        )
    except InputError:
        raise
    except (OSError, KeyError, ValueError, ElementTree.ParseError, DefusedXmlException):
        raise InputError("invalid or unsafe CFDI XML") from None


def load_catalog(path: Path = CATALOG_PATH) -> dict:
    """Verify the frozen extraction against the host's shipped manifest."""
    try:
        manifest = json.loads((FIXTURES / "catalog_manifest.json").read_text())
        raw = path.read_bytes()
        if not manifest.get("source_sha256") or not manifest.get("retrieved_on"):
            raise ValueError("unpinned source")
        if hashlib.sha256(raw).hexdigest() != manifest["catalog_sha256"]:
            raise ValueError("hash mismatch")
        catalog = json.loads(raw)
        if not catalog["uses"] or not catalog["regimes"]:
            raise ValueError("empty catalog")
        return catalog
    except (OSError, ValueError, KeyError, TypeError):
        raise InputError("missing, invalid or unpinned catalog") from None


def load_inputs(xml_paths, profile_path, bank_path, catalog_path):
    catalog = load_catalog(catalog_path)
    try:
        profile = Profile.model_validate_json(Path(profile_path).read_text())
        if (not RFC.fullmatch(profile.receiver_rfc)
                or len(profile.receiver_rfc) != (13 if profile.person_type == "fisica" else 12)):
            raise InputError("invalid profile RFC syntax/person type")
        regime = catalog["regimes"].get(profile.fiscal_regime)
        if not regime or profile.person_type not in regime["person_types"]:
            raise InputError("invalid profile fiscal regime/person type")
        with Path(bank_path).open(newline="", encoding="utf-8") as source:
            reader = csv.DictReader(source)
            if reader.fieldnames != ["transaction_id", "date", "amount_mxn", "description"]:
                raise InputError("invalid bank CSV columns")
            bank = [BankTransaction(transaction_id=r["transaction_id"], date=r["date"],
                                    amount_mxn=money(r["amount_mxn"])) for r in reader]
        invoices = [parse_invoice(Path(path)) for path in xml_paths]
        if not invoices or len({i.invoice_uuid for i in invoices}) != len(invoices):
            raise InputError("empty input or duplicate invoice UUID")
        if len({b.transaction_id for b in bank}) != len(bank):
            raise InputError("duplicate bank transaction ID")
        return invoices, profile, bank, catalog
    except InputError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise InputError("invalid profile or bank input") from None


def match_invoices(invoices, profile, bank, catalog) -> list[Finding]:
    """Match calendar dates [issue date, issue date + 7 days], not elapsed hours.

    Positive bank entries never qualify. Shared candidates across invoices make
    every affected invoice ambiguous, avoiding an arbitrary first-wins match.
    """
    findings, candidates = [], {}
    def active(row, day):
        return (row and row["valid_from"] <= day.isoformat()
                and (row["valid_until"] is None or day.isoformat() <= row["valid_until"]))
    for inv in invoices:
        use = catalog["uses"].get(inv.use)
        regime = catalog["regimes"].get(inv.fiscal_regime)
        if inv.receiver_rfc != profile.receiver_rfc:
            status, reason = "mismatch", "receiver_mismatch"
        elif inv.fiscal_regime != profile.fiscal_regime:
            status, reason = "mismatch", "regime_mismatch"
        elif not use or not regime:
            status, reason = "needs_review", "catalog_code_unknown"
        elif not (active(use, inv.issued_on) and active(regime, inv.issued_on)):
            status, reason = "needs_review", "catalog_date_outside_validity"
        elif (inv.fiscal_regime not in use["regimes"]
              or profile.person_type not in use["person_types"]
              or profile.person_type not in regime["person_types"]):
            status, reason = "mismatch", "use_regime_incompatible"
        elif (inv.kind != "I" or inv.currency != "MXN" or inv.method != "PUE"
              or inv.unsupported_structure):
            status, reason = "needs_review", "outside_mvp_scope"
        else:
            hits = [b.transaction_id for b in bank if b.amount_mxn < 0
                    and -b.amount_mxn == inv.total and 0 <= (b.date - inv.issued_on).days <= 7]
            candidates[inv.invoice_uuid] = hits
            status, reason = (("matched", "exact_candidate") if len(hits) == 1 else
                              ("ambiguous", "multiple_candidates") if hits else
                              ("needs_review", "no_exact_candidate"))
        hits = candidates.get(inv.invoice_uuid, [])
        findings.append(Finding(
            invoice_uuid=inv.invoice_uuid, status=status, reason_code=reason,
            bank_transaction_id=hits[0] if status == "matched" else None,
            evidence_ids=["invoice:" + inv.invoice_uuid, "catalog:20261106"] + ["bank:" + h for h in hits],
        ))
    counts = Counter(t for hits in candidates.values() for t in hits)
    return [f.model_copy(update={"status": "ambiguous", "reason_code": "shared_bank_candidate",
                                 "bank_transaction_id": None})
            if any(counts[t] > 1 for t in candidates.get(f.invoice_uuid, [])) else f for f in findings]


def exact_match_required(request: GovernorInput) -> bool:
    """True means violation. Only the host can populate/consume allowed pairs."""
    action = request.action
    if action is None or action.tool_name != "mark_reconciled":
        return False
    args = action.arguments
    pair = {k: args.get(k) for k in ("invoice_uuid", "bank_transaction_id")}
    state = request.context.state
    allowed, consumed = state.get("allowed_pairs"), state.get("ledger_pairs")
    if not all(isinstance(v, str) and v for v in pair.values()):
        return True
    if not isinstance(allowed, list) or not isinstance(consumed, list) or pair not in allowed:
        return True
    return any(not isinstance(p, dict) or any(p.get(k) == v for k, v in pair.items()) for p in consumed)


RULES = RuleCatalog(runtime_rules={"cfdi.exact_match_required": exact_match_required})


class LocalLedger:
    """Atomic replacement in a single-process demo; not a concurrent database."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.rows = self.read()

    def read(self):
        if not self.path.exists():
            return []
        try:
            rows = [LedgerRow.model_validate(r).model_dump() for r in json.loads(self.path.read_text())]
            for key in ("invoice_uuid", "bank_transaction_id"):
                if len({r[key] for r in rows}) != len(rows):
                    raise ValueError("duplicate")
            return rows
        except (OSError, ValueError, TypeError):
            raise InputError("invalid local ledger") from None

    def write(self, proposal: ActionProposal, *, run_id: str, authorized: bool):
        pair = {k: proposal.arguments[k] for k in ("invoice_uuid", "bank_transaction_id")}
        if any(any(row[k] == v for k, v in pair.items()) for row in self.rows):
            raise ValueError("local ledger uniqueness violation")
        row = LedgerRow(**pair, run_id=run_id, authorized_by_host=authorized).model_dump()
        next_rows = [*self.rows, row]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", dir=self.path.parent, delete=False, encoding="utf-8") as handle:
                temporary = Path(handle.name)
                json.dump(next_rows, handle, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        self.rows = next_rows
        return "recorded in local demonstration ledger"


def scripted_model(proposals: list[dict], output: dict) -> FunctionModel:
    """Replay tool proposals, then emit a typed-output tool call. No provider."""
    def respond(messages, info):
        previous = sum(1 for msg in messages for p in msg.parts
                       if getattr(p, "part_kind", None) == "tool-call" and p.tool_name == "mark_reconciled")
        if previous < len(proposals):
            return ModelResponse(parts=[ToolCallPart("mark_reconciled", proposals[previous])])
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, output)])
    return FunctionModel(respond)


class _GovernorAbort(Exception):
    pass


@dataclass
class _Deps:
    controller: WorkflowController
    context: ExecutionContext
    ledger: LocalLedger
    actions: list


@dataclass(frozen=True)
class CfdiRun:
    run_id: str
    mode: str
    state: str
    findings: tuple[Finding, ...]
    actions: tuple
    ledger_rows: tuple[dict, ...]
    agent_output: ReconciliationReport | None


def run_reconciliation(*, xml_paths, profile_path, bank_path, run_id: str,
                       ledger_path: Path, catalog_path: Path = CATALOG_PATH,
                       contract_path: Path = CONTRACT_PATH, mode="guarded",
                       model: Any = None, recorder=None, telemetry=None,
                       force_attempt=False, repeat_attempt=False) -> CfdiRun:
    """Validate host inputs before the agent; gate every ledger write.

    ``force_attempt``/``repeat_attempt`` drive adversarial scripted fixtures only.
    A caller-supplied model cannot supply authorization facts. Output validation
    checks semantics against host findings, but cannot undo earlier tool effects.
    """
    invoices, profile, bank, catalog = load_inputs(xml_paths, profile_path, bank_path, catalog_path)
    findings = match_invoices(invoices, profile, bank, catalog)
    ledger = LocalLedger(ledger_path)
    allowed = [{"invoice_uuid": f.invoice_uuid, "bank_transaction_id": f.bank_transaction_id}
               for f in findings if f.status == "matched"]
    controller = WorkflowController.from_contract_path(
        contract_path, run_id, policy=EnforcementPolicy(mode=mode),
        rule_catalog=RULES, recorder=recorder, telemetry=telemetry,
    )
    context = ExecutionContext(
        state={"allowed_pairs": allowed, "ledger_pairs": [
            {k: r[k] for k in ("invoice_uuid", "bank_transaction_id")} for r in ledger.rows]},
        available_tools=["mark_reconciled"], observed_agent_fingerprint="cfdi-agent-v1",
        observed_contract_fingerprint=controller.contract.contract_fingerprint,
    )
    expected = ReconciliationReport(items=findings)
    if model is None:
        proposals = ([{"invoice_uuid": f.invoice_uuid, "bank_transaction_id":
                       f.bank_transaction_id or (bank[0].transaction_id if bank else "unknown")}
                      for f in findings] if force_attempt else allowed)
        if repeat_attempt:
            proposals = proposals * 2
        model = scripted_model(proposals, expected.model_dump(mode="json"))
    actions, output = [], None
    span = telemetry.run(run_id, controller.contract.contract_id) if telemetry else nullcontext()
    with span:
        controller.begin(context)
        if controller.state == "active":
            agent = Agent(model, deps_type=_Deps, output_type=ReconciliationReport,
                          instructions="Use only the supplied host findings. Never invent a match. Return all findings.",
                          retries=1)

            @agent.tool(sequential=True)
            def mark_reconciled(ctx: RunContext[_Deps], invoice_uuid: str, bank_transaction_id: str) -> str:
                """Request a write to the host's governed demonstration ledger."""
                proposal = ActionProposal(tool_name="mark_reconciled", arguments={
                    "invoice_uuid": invoice_uuid, "bank_transaction_id": bank_transaction_id})
                def effect(p):
                    pair = {k: p.arguments[k] for k in ("invoice_uuid", "bank_transaction_id")}
                    return ctx.deps.ledger.write(p, run_id=run_id, authorized=pair in allowed)
                outcome = ctx.deps.controller.execute(proposal, ctx.deps.context, effect)
                ctx.deps.actions.append(outcome)
                if ctx.deps.controller.state != "active":
                    raise _GovernorAbort()
                if not outcome.executed:
                    return "blocked by Governor: " + ", ".join(v.rule for v in outcome.decision.violations)
                ctx.deps.context.state["ledger_pairs"] = [
                    {k: r[k] for k in ("invoice_uuid", "bank_transaction_id")} for r in ctx.deps.ledger.rows]
                return outcome.result

            @agent.output_validator
            def verify_output(result: ReconciliationReport) -> ReconciliationReport:
                if result != expected:
                    raise ModelRetry("Output must agree exactly with the supplied host findings")
                return result

            try:
                output = agent.run_sync(
                    expected.model_dump_json(), deps=_Deps(controller, context, ledger, actions),
                    usage_limits=UsageLimits(request_limit=12, tool_calls_limit=10),
                ).output
            except _GovernorAbort:
                pass
            if controller.state == "active":
                controller.finish(context, {"status": "reviewed", "ledger_rows": ledger.read(),
                                            "findings": expected.model_dump(mode="json")["items"]})
    return CfdiRun(run_id, mode, controller.state, tuple(findings), tuple(actions), tuple(ledger.read()), output)


def case_inputs(case: str) -> dict:
    item = json.loads((FIXTURES / "scenarios.json").read_text())[case]
    return {"xml_paths": [FIXTURES / item["xml"]], "profile_path": FIXTURES / "profile.json",
            "bank_path": FIXTURES / item["bank"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=["no_contract", "advisory", "guarded", "strict"], default="guarded")
    parser.add_argument("--xml-dir", type=Path, help="Directory of XML invoices for one batch")
    parser.add_argument("--profile", type=Path, help="Trusted recipient profile JSON")
    parser.add_argument("--bank", type=Path, help="Bank CSV with negative expense amounts")
    args = parser.parse_args()
    supplied = (args.xml_dir, args.profile, args.bank)
    custom_batch = any(value is not None for value in supplied)
    if custom_batch and not all(value is not None for value in supplied):
        parser.error("--xml-dir, --profile and --bank must be supplied together")
    if custom_batch:
        if not args.xml_dir.is_dir():
            parser.error("--xml-dir must be an existing directory")
        jobs = [("batch", {"xml_paths": sorted(p for p in args.xml_dir.iterdir()
                                               if p.is_file() and p.suffix.lower() == ".xml"),
                            "profile_path": args.profile, "bank_path": args.bank})]
    else:
        jobs = [(case, case_inputs(case)) for case in ("A", "B", "C", "D", "E", "F", "F_VERSION")]
    from opentelemetry.sdk.trace import TracerProvider
    provider = TracerProvider()
    telemetry = TelemetryObserver(provider)
    # A fresh subdirectory avoids reusing previous evidence or ledger effects.
    output_dir = args.output_dir / str(uuid4())
    log = JsonlDecisionLog(output_dir / "events.jsonl")
    try:
        for case, inputs in jobs:
            run_id = f"cfdi-{output_dir.name}-{case}"
            try:
                run = run_reconciliation(**inputs, run_id=run_id,
                    ledger_path=output_dir / f"{case}-ledger.json", mode=args.mode,
                    recorder=log, telemetry=telemetry, force_attempt=not custom_batch)
            except InputError as error:
                print(json.dumps({"event": "input_rejected", "case": case, "run_id": run_id,
                                  "reason": str(error), "agent_started": False}))
                if custom_batch:
                    return 1
                continue
            for event in log.read():
                if event.run_id == run_id:
                    print(event.model_dump_json())
            counts = Counter(f.status for f in run.findings)
            print(json.dumps({"event": "host_verified_result", "case": case,
                "run_id": run_id, "mode": args.mode, "state": run.state,
                **{s: counts[s] for s in ("matched", "mismatch", "ambiguous", "needs_review")},
                "ledger_rows": len(run.ledger_rows), "authorized_rows": sum(r["authorized_by_host"] for r in run.ledger_rows),
                "findings": [f.model_dump(mode="json") for f in run.findings],
                "trace_id": next(e.trace_id for e in log.read() if e.run_id == run_id)}))
        print(json.dumps({"event": "artifacts", "directory": str(output_dir), "log": str(output_dir / "events.jsonl")}))
    finally:
        provider.shutdown()
    return 0


if __name__ == "__main__":
    exit_code = main()
    if exit_code:
        raise SystemExit(exit_code)
