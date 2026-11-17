<!-- Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
SPDX-License-Identifier: Apache-2.0 -->

# Contexto confiable aportado por el host

En la arquitectura de Governor Contracts, la separación de privilegios entre el modelo de lenguaje (LLM/agente) y el entorno de ejecución (host application) es absoluta y crítica para la seguridad del sistema.

## Separación estricta de fuentes de datos

- **`ExecutionContext`**: Este objeto encapsula el estado confiable observado y gestionado exclusivamente por la aplicación anfitriona (host). Los hechos contenidos en `ExecutionContext.state` —tales como la bandera booleana `approval_granted` o los identificadores de documentos recuperados observados por el host (`retrieved_doc_ids`)— provienen únicamente de fuentes seguras del host (por ejemplo, almacenes de sesión validados, flujos de autenticación o el componente de recuperación del host).
- **`ActionProposal.arguments`**: Son los argumentos propuestos libremente por el modelo de lenguaje o agente al solicitar la ejecución de una herramienta. Bajo ninguna circunstancia `ActionProposal.arguments` debe ser considerado fuente de autorización o de verdad contextual.

## Inviolabilidad de las decisiones de gobernanza

Las reglas de tiempo de ejecución evalúan la validez de una acción basándose en hechos confiables del `ExecutionContext`. Si un agente intenta falsificar su estado de autorización o inyectar identificadores no recuperados dentro de sus propios argumentos (`ActionProposal.arguments`), la puerta del host ignorará dichas afirmaciones y validará contra el estado real del host. Los argumentos del agente representan una *propuesta no confiable*; la autorización y el contexto provienen únicamente del host.
