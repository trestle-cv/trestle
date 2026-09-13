# Trestle engineering handover

## Frontend asset ownership

Nift tracks and builds HTML pages only. CSS, JavaScript, images, icons and other
static assets are canonical in the generated web root (`public/`, `web/dist/`
or the repository's embedded-public directory). Edit those files directly.
Do not recreate asset copies under `content/`, do not add asset entries to
`.nift/tracked.json`, and do not let a Nift build overwrite them. After changing
HTML templates or content, run Nift and verify that direct assets are unchanged.

Trestle is an open-source, self-hosted application backend. It provides
collections, authentication, access rules, files, realtime events, migrations,
administration, audit, backups, and event-driven integrations from one compact
Go executable with an embedded Nift-built web interface, a SQLite foundation and
PostgreSQL as an available external-database option.

The canonical module and repository are intended to be:

```text
github.com/trestle-cv/trestle
```

The project is in pre-release hardening in preparation for an honest public
preview. Do not describe planned capabilities as implemented, and do not present
Trestle as battle-proven, highly available, or production-ready. `CHECKPOINTS.md`
is the completed step-by-step execution handover; `PLAN.md` is the phase map;
`POSTGRES-CHECKPOINTS.md` records the completed PostgreSQL parity campaign;
`PREVIEW-CHECKPOINTS.md` is the active public-preview campaign.
`ARCHITECTURE.md`, `API.md`, `UI.md`, `FUNCTIONS.md`, and `SECURITY.md` define
the initial contracts. Keep them aligned as implementation turns decisions into
tested behaviour.

`PREVIEW-CHECKPOINTS.md` is the active campaign preparing an honest public
preview: PostgreSQL battle-hardening, SQLite/PostgreSQL parity proof, product
hardening, reproducible releases and installers, the public domain (`trestle.cv`)
and website, and a final publish/no-publish review. Its checkpoints are named
CP1-CP22 and are distinct from the completed CP00-CP23 and PG00-PG12 campaigns.
The preview positioning is intentionally restrained: an early preview for
evaluation and prototypes, never presented as battle-proven, highly available,
or immune to outages because it is self-hosted. Do not publicise Trestle until
the publish gate in `PREVIEW-CHECKPOINTS.md` authorizes it.

## Implementation handover

Work through `CHECKPOINTS.md` in order. A checkpoint is not complete merely
because its code exists: the dashboard slice, public website/documentation
slice, tests, evidence record, and repository commits listed there are part of
the same definition of done. Do not silently combine checkpoints or mark later
work complete because an early abstraction appears capable of supporting it.

The public site is developed continuously in the sibling
`../trestle-cv.github.io` repository. It must be a substantial multi-page Nift
site using minimalist dark-mode design and vanilla CSS/JavaScript. Add or deepen
the relevant documentation when each product capability becomes real. Do not
write the whole future manual at the beginning, and do not defer the website to
the end. Planned features may be explained only when visibly labelled planned.

## Product position

Trestle has its own API, schema, migration, token, filter-language, and
behavioural contracts. Build from Trestle's product requirements and do not
copy another product's implementation or UI. Import tools may translate data,
but external compatibility is not the canonical architecture.

The API is the product. SDKs are conveniences. Any language capable of HTTP,
JSON, and streaming HTTP must be able to use the full supported application
surface. Trestle must support both:

```text
browser/mobile → user session → Trestle rules → data/files/realtime

browser → backend in any language → scoped service identity → Trestle
```

Never require a superuser credential for ordinary application-backend access.

## Non-negotiable product decisions

1. Go server, SQLite first, and one normal release executable.
2. Nift builds the frontend; generated assets are embedded in the Go binary.
3. The dashboard uses vanilla HTML, CSS, and JavaScript. Do not introduce a
   frontend framework or rebuild one accidentally through opaque abstractions.
4. Dark mode is the authored primary theme. Light/system may follow.
5. The dashboard occupies exactly the viewport. `html`, `body`, and the root
   application shell never scroll horizontally or vertically. Only deliberate
   panes, tables, drawers, editors, dialogs, logs, and timelines may scroll.
6. Application, administration, and system APIs have distinct authority.
7. Collection filters and access rules use parsed, typed ASTs compiled to
   parameterized queries; never concatenate user expressions into SQL.
8. Authentication, authorization, migrations, jobs, realtime, retention, and
   audit remain deterministic software - not model decisions.
9. AWS Lambda invocation from committed application events is the first
   functions integration. Trestle remains useful without AWS.
10. User-defined local function execution is deferred until a credible process
    isolation and capability model exists.
11. Public guarantees require regression evidence, not implementation intent.

## Initial domain vocabulary

- **Project**: one logical application boundary inside a Trestle deployment.
  Single-project operation comes first; do not assume multi-project isolation
  is implemented merely because the domain name exists.
- **Collection**: schema and policy describing a class of records.
- **Base collection**: ordinary application records.
- **Auth collection**: records that may authenticate as application users.
- **View collection**: read-only query-backed projection, deferred initially.
- **Record**: one durable collection value with stable ID and version metadata.
- **Rule**: deterministic authorization condition for an operation.
- **Actor**: authenticated user, service account, personal token, function
  grant, or superuser responsible for an operation.
- **Service account**: scoped identity for a trusted application backend.
- **Event**: versioned fact emitted after a committed state transition.
- **Job**: durable claimed work with attempts, leases, and terminal state.
- **Function integration**: provider adapter invoked from an event; AWS Lambda
  is first.
- **Function grant**: short-lived, narrowly scoped identity allowing an invoked
  function to call Trestle back.

Use these terms consistently in packages, schema, APIs, UI, docs, and tests.

## Engineering workflow

Before substantial work:

1. Read this entire file and every task-relevant contract document.
2. Inspect repository status and preserve unrelated work.
3. Identify the user-visible contract and failure modes being changed.
4. Define verification before broad implementation.

For every coherent checkpoint:

1. Implement the smallest complete vertical slice.
2. Add unit, integration, migration, authorization, concurrency, and
   adversarial coverage appropriate to it.
3. Run formatting, static analysis, tests, race checks, production builds, and
   frontend/Nift checks.
4. Inspect the complete diff and repository status.
5. Update `CHECKPOINTS.md` with evidence and remaining uncertainty; update
   `PLAN.md` only when the phase-level plan changes.
6. Complete the checkpoint's website/documentation slice and verify its claims
   against the implementation.
7. Commit the coherent checkpoint. Commit generated website output separately
   where a nested output repository requires it.

Expected Go-era baseline gates once implementation exists:

```sh
gofmt -w <changed Go files>
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/trestle
nift build
nift status
node --check <changed JavaScript files>
```

Release builds should cover Linux, macOS, and Windows on amd64 and arm64 unless
a target is deliberately unsupported and documented.

## Migration lineage workflow

The pre-preview migration lineage is frozen in
`internal/store/migrations_manifest.json` and enforced by
`TestMigrationLineageFrozen`: retained versions, names and normalized SQLite
and PostgreSQL DDL digests must never change. To add a new migration:

1. Append migration `N+1` to the SQLite and PostgreSQL migration tables and bump
   `CurrentVersion`.
2. Run the append-only manifest updater:
   `TRESTLE_LINEAGE_WRITE=1 go test ./internal/store -run TestUpdateMigrationLineageManifest -count=1`
   It validates every retained entry against the compiled migrations, appends
   exactly the new version's entry, and refuses to write anything if a retained
   version, name or digest changed.
3. Commit the new migration, the regenerated manifest and the tests together.
   Running the updater with no new migration is a no-op.

Never hand-edit the manifest or use it to bless a rewritten historical
migration.

## Repository neighbours

The public website source is the sibling `trestle-cv.github.io` repository;
its generated deployment output is a nested `public/` repository. Website
claims must match implemented and verified milestones here.

## Release handover and installer deployment invariant

Every release is an evidence gate. If `install.sh` or `update.sh` changed since
the previous release, its exact reviewed version must be incorporated into the
website source and generated output, deployed publicly, downloaded again,
byte-compared or checksum-compared with the canonical script, syntax-checked,
and exercised before creating a release tag:

```text
script changed
-> website source updated
-> generated website rebuilt
-> website deployed
-> public bytes verified
-> candidate installation smoke
-> release authorization
-> tag and publication
-> post-release public installation smoke
```

If neither script changes during a release, no installer deployment is required
for that release, but the invariant still governs any future release that does
change them.

## Current release state

- Released: **v0.1.4** (stable public preview). The canonical Gantry account
  model, headless setup, confirmed reset commands, and installed-service reset
  targeting are included in this release.
- Development: **0.1.4** on `main`. An ordinary development build reports
  0.1.4 with commit `unknown`; release builds override the default via ldflags
  and are never confused with the development identity.
- After publishing a stable release, advance the buildinfo default and its
  exact-version test to the next patch, record the released/development
  versions here, and leave public website claims on the actual released
  version until the next release is published.

---

# Nift project handover
v0.0.5

This is a living handover for working effectively in a Nift project.

Canonical version:

https://nift.dev/HANDOVER.md

Check the version at the top of this file against the canonical copy when the
project is old, unfamiliar, or behaving differently from the current Nift
documentation.

To replace this file with the latest canonical version:

```sh
curl -fsSL https://nift.dev/HANDOVER.md -o HANDOVER.md
```

If this project has project-specific additions, preserve or reapply them when
updating the canonical handover.

This project uses Nift as part of its website build process.

Nift is the project's build-time templating and dependency layer. It does not determine what the website is about or what other technologies the project should use.

Keep the existing project architecture and use the project's normal HTML, CSS, JavaScript, frameworks, backend, and other tooling where appropriate.

Do not introduce Nift-specific machinery where ordinary web tooling is the clearer solution.

## Start here

Before making substantial changes:

1. Inspect `.nift/config.json` and `.nift/tracked.json`.
2. Inspect the existing `content/`, `templates/`, and output structure.
3. Read this project's `README.md` and other project-specific documentation.
4. Run:

```sh
nift status
```

During normal development, build frequently:

```sh
nift build
```

Use this throughout a task, not only at the end. Rebuild after meaningful
changes so Nift can surface template, path, dependency, configuration, and
tracking errors while the cause is still obvious.

In particular, run `nift build` immediately after editing
`.nift/config.json` or `.nift/tracked.json`.

Use:

```sh
nift status
```

when you want to inspect what Nift considers stale and why.

Successful `nift build` output may include indented `↳ ...` lines explaining
why a page was considered stale and rebuilt, such as a missing generated output
or a changed dependency. These are rebuild reasons, not errors. Actual build
failures are reported as errors and cause the build to fail.

Do not delete or recreate `.nift/`.

## Nift's core template model

Most Nift websites need very little Nift-specific syntax.

The three primitives you will use most often are:

```text
@content
@input(...)
@path(...)
```

`@content` inserts the tracked page's content into its template.

```html
<main>
    @content
</main>
```

`@content` should execute exactly once across the rendered template/input graph
for a tracked page. It is normally placed in the page's template; the tracked
content file supplies the content inserted there.

Content files may still use other Nift syntax when needed. If page text needs
to display Nift syntax literally, prefix the active sigil with `\` rather than
leaving it as template syntax:

```html
<code>\@content</code>
<code>\@path('about')</code>
<code>\$[title]</code>
```

This applies whenever `@...`, `$[...]`, or other Nift syntax is intended as
literal output rather than something Nift should execute or resolve.

`@input(...)` inserts a reusable file and automatically makes it a dependency of the output using it.

```html
@input('templates/header.html')

<main>
    @content
</main>

@input('templates/footer.html')
```

`@path(...)` creates project-aware links to tracked pages and local assets.

Nift has additional features including metadata, JSON data, loops, conditionals, pagination, contracts, and explicit dependencies. Use them when the project actually needs them; do not use advanced features merely because they exist.

When writing expressions inside constructs such as `@if(...)`, refer to values directly rather than wrapping them in `$[...]`. For example:

```html
@if(name == 'about'){...}
```

Use `$[...]` when resolving or rendering a value into output, for example `$[title]`. Consult the expressions and control-flow documentation when using more advanced expression syntax.

## Internal links: use `@path`

Use `@path(...)` for internal links.

This applies to:

- links between pages;
- stylesheets;
- JavaScript;
- images and other local assets where Nift should know the relationship.

For pages, link to the **tracked page name**, not its generated file.

```html
<nav>
    <a href="@path('/')">Home</a>
    <a href="@path('about')">About</a>
    <a href="@path('docs')">Docs</a>
    <a href="@path('contact')">Contact</a>
</nav>
```

Do this:

```html
<a href="@path('about')">About</a>
```

Do not do this:

```html
<a href="@path('about.html')">About</a>
```

and do not hard-code the generated output path:

```html
<a href="about.html">About</a>
```

The tracked page name is the stable project identity. Its output filename or location may change independently.

CSS and JavaScript includes should also use `@path(...)`:

```html
<link rel="stylesheet" href="@path('public/assets/style.css')">
<script src="@path('public/assets/app.js')"></script>
```

Do not calculate relative paths such as:

```html
<link rel="stylesheet" href="../../assets/style.css">
```

Using `@path` lets Nift resolve the correct output-relative path and check the project relationship during the build.

## Project configuration

`.nift/config.json` contains project-level Nift configuration.

`.nift/tracked.json` describes tracked pages and their metadata, including things such as their content, template, and output relationships.

These files are part of the project and should evolve with its structure.

If you add, remove, or reorganise pages, templates, outputs, deployment settings, or other Nift-managed structure, inspect the relevant `.nift` configuration and update it where necessary.

Do not treat `.nift/` as disposable generated state.

Do not invent `.nift/tracked.json` fields or assume arbitrary fields become
`$[...]` metadata. When you need tracking behaviour or metadata that is not
already demonstrated by the project, consult the tracked-files and metadata
documentation rather than guessing.

## Output directory

Do not assume the generated website always lives in `public/`.

A normal Nift project may use `public/`, but deployment targets can use a different output structure appropriate to the platform.

Inspect `.nift/config.json` before making assumptions about output paths.

Edit source files rather than generated output unless the project explicitly documents otherwise.

## Pagination

Pagination has several related pieces across `.nift/tracked.json`, page
content, pagination templates, and generated page links. Do not infer its full
behaviour from this handover.

If working with pagination, read the dedicated documentation first:

https://nift.dev/docs/pagination.html

Preserve the project's existing pagination structure unless the task actually
requires changing it, and run `nift build` frequently while doing so.

## Other stacks and tools

Nift does not need to own the whole application.

A project may use Nift alongside tools such as Vite, React, Vue, Svelte, TypeScript, Go, Node, Python, PHP, serverless functions, or other systems.

Keep responsibilities separated:

- use Nift for build-time composition, tracked relationships, and dependencies;
- use the neighbouring tool for the job it is designed to do.

Do not replace an existing stack with Nift-specific code simply to make more of the project use Nift.

## Before finishing

Run:

```sh
nift build
nift status
```

The build should succeed and `nift status` should report the project up to date.
Spot-check generated output when changes affect paths, templates, tracked
relationships, or deployment structure.

## Documentation

Nift documentation:

https://nift.dev/docs.html

When unfamiliar with the project, prioritise:

1. Getting started - https://nift.dev/docs/getting-started.html
2. the three-primitives/template-language material;
3. paths and tracked files, especially `@path`;
4. project structure;
5. `.nift/config.json` and `.nift/tracked.json`;
6. incremental builds and CLI commands.

Then read feature documentation only when the task requires it, for example:

- JSON and control flow;
- pagination;
- contracts;
- minification;
- deployment targets;
- integration with other application stacks.

Prefer documented Nift behaviour and the existing project structure over guessing based on another website generator or framework.
