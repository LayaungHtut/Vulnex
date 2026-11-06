# VULNEX

Vulnerability scanning platform. Early stage: the repository currently holds a SvelteKit + TypeScript scaffold. Architecture is pending the first spec from the Chief Architect (see [docs/WORKFLOW.md](docs/WORKFLOW.md)).

## Stack

SvelteKit 3 · Svelte 5 · TypeScript · Tailwind CSS 4 · Vitest · Playwright · ESLint · Prettier · npm

## Develop

```sh
npm install
npm run dev        # dev server
npm run check      # type check
npm run lint       # prettier + eslint
npm run test:unit  # vitest
npm run test       # unit + e2e
```

## How work happens here

Three AI agents with separate roles, orchestrated by the founder. No agent approves its own work. Read [docs/WORKFLOW.md](docs/WORKFLOW.md) before contributing.
