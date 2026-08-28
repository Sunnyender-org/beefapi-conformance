# Harbor tasks

These tasks follow Harbor schema 1.1 and test agent behavior independently of a
specific client adapter. Install Harbor from its official repository, configure
the chosen native agent with a BeefAPI test route, then point Harbor at `tasks/`.

The local-tool task is intentionally deterministic: the agent must read a file
through its own tool path and write the observed value to a verifier-owned
location. Add tool, web, lifecycle, and media tasks as their verifiers are
migrated from the legacy certifier.

Harbor tasks do not enter `compile_matrix` and cannot replace a released-client
cell. They provide portable task/trajectory evidence; the local runner remains
the authority for exact installed CLI behavior and BeefAPI server read-back.

Pinned development reference at repository creation: Harbor commit
`f5f6b84c2ded2bad9ef6474030ae6492fc99c6d2`.
