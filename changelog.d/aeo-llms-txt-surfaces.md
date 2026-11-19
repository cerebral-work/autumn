### Added

- **aeo:** `llms.txt` discovery across all Autumn web surfaces:
  - Core `autumn-web` AEO `/llms.txt` now renders a deterministic `## API Endpoints` section from non-hidden registered `ApiDoc` routes (capped at 50 inline endpoints with an `OpenAPI` pointer when truncated) so API-only and orchestrator services expose route summaries alongside pages and agent entry points.
  - `autumn-admin-plugin` mounts `GET {prefix}/llms.txt` inside the admin role guard (with `describedby` link discovery on the admin layout and dashboard) summarizing registered models and CRUD surfaces.
  - `autumn-edge` automatically serves `GET /llms.txt` summarizing registered edge routes and capability needs unless overridden by an explicit `/llms.txt` route.
  - `autumn-web` Actuator mounts `GET {prefix}/llms.txt` listing active observability and diagnostic endpoints according to profile sensitivity and Prometheus configuration.
