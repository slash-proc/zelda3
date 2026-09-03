#!/usr/bin/env node
// Emits the release manifest that a consuming tool reads to discover, verify
// and drive this project's extractor.
//
// The manifest is the entry point, not the trust root. It carries the module's
// sha256, so a consumer that trusts the manifest's origin can check it got the
// right bytes -- but everything security-relevant (imports, exports, memory
// bounds) is re-derived from the binary by `verify.mjs` and must agree. A
// manifest that claimed a module imported nothing would not make it so.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { verify, DEFAULT_POLICY } from "./verify.mjs";

const [wasmPath, outPath] = process.argv.slice(2);
if (!outPath) {
  console.error("usage: manifest.mjs <module.wasm> <manifest.json>");
  process.exit(2);
}

const bytes = new Uint8Array(readFileSync(wasmPath));
const result = verify(bytes);
if (!result.ok) {
  console.error("refusing to publish a non-conformant module:");
  for (const e of result.errors) console.error(`  - ${e}`);
  process.exit(1);
}

// Output hashes are a function of (input x options), so they cannot be stated
// unconditionally. `check.sh` records the hashes of a real reference run into
// reference.json; when that exists we publish it, and when it does not we
// publish nothing rather than a hash we cannot stand behind.
const REFERENCE = "reference.json";
const reference = existsSync(REFERENCE) ? JSON.parse(readFileSync(REFERENCE, "utf8")) : null;

// Localised strings are {en, fr, de} objects. `en` is the base and is always
// present; a consumer falls back to it for any locale it has no entry for.
const loc = (en, fr, de) => ({ en, fr, de });

const env = process.env;
const isTag = env.GITHUB_REF_TYPE === "tag";
const manifest = {
  schemaVersion: 1,
  // The project-independent extractor spec this repo implements. A consumer
  // keyed to spec 1 knows what every field below means.
  spec: 1,
  project: "zelda3",
  title: "The Legend of Zelda: A Link to the Past",
  // What to call the game where a full cartridge title would wrap or crowd a
  // control. The long title stays authoritative; this is presentation.
  shortTitle: "Zelda 3",
  source: {
    repo: env.GITHUB_REPOSITORY ?? null,
    commit: env.GITHUB_SHA ?? null,
    ref: env.GITHUB_REF_NAME ?? null,
    workflow: env.GITHUB_RUN_ID
      ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/actions/runs/${env.GITHUB_RUN_ID}`
      : null,
  },
  docs: {
    readme: "tables/wasm/README.md",
    spec: "docs/spec/",
  },
  tools: [
    {
      id: "zelda3-assets",
      kind: "asset-extractor",
      title: "Zelda 3 asset conversion",
      // Human-readable requirements: what the user must supply and what they
      // get back. A UI can show this verbatim.
      readme: "tables/wasm/PROJECT.md",

      // What the consumer must check before running the module.
      module: {
        file: wasmPath.split("/").pop(),
        bytes: bytes.length,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        // Fetch the module from the same directory as this manifest. Release
        // assets are deliberately not used here: they are not CORS-fetchable
        // from a browser (see docs/spec/distribution.md), so a consuming web
        // tool cannot read them. The release URL below is the archival copy of
        // the identical bytes, for humans and non-browser consumers.
        url: wasmPath.split("/").pop(),
        releaseUrl: env.GITHUB_REPOSITORY && isTag
          ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}/releases/download/${env.GITHUB_REF_NAME}/${wasmPath.split("/").pop()}`
          : null,
      },

      // The declared contract. A consumer re-derives this from the binary and
      // compares; the manifest is a convenience, never the source of truth.
      abi: {
        version: 1,
        imports: result.info.imports,
        exports: result.info.exports.map((e) => ({ name: e.name, kind: e.kind })),
        memory: result.info.memories,
      },
      policy: {
        allowImports: DEFAULT_POLICY.allowImports,
        allowStartSection: DEFAULT_POLICY.allowStartSection,
        maxMemoryPages: DEFAULT_POLICY.maxMemoryPages,
      },

      // The input files this tool accepts, as named roles. Role is resolved by
      // the module from file content, never from order or a host-supplied
      // name; these entries exist so a UI can tell the user what to supply and
      // reject an obviously wrong file before spending a run.
      inputs: [
        {
          id: "base",
          required: true,
          repeatable: false,
          label: loc(
            "Base ROM",
            "ROM de base",
            "Basis-ROM",
          ),
          description: loc(
            "US (NTSC) cartridge dump.",
            "Copie de la cartouche US (NTSC).",
            "Kopie der US Fassung (NTSC).",
          ),
          extensions: [".sfc", ".smc"],
          maxBytes: 8 * 1024 * 1024,
          variants: [
            {
              id: "us",
              language: "us",
              label: loc(
                "The Legend of Zelda: A Link to the Past (USA, NTSC)",
                "The Legend of Zelda: A Link to the Past (USA, NTSC)",
                "The Legend of Zelda: A Link to the Past (USA, NTSC)",
              ),
              sha1: "6D4F10A8B10E10DBE624CB23CF03B88BB8252973",
              bytes: 1048576,
            },
          ],
          // Unlike a project whose whole point is running modified ROMs, there
          // is no legitimate Zelda 3 base ROM that fails this hash: the port
          // reads fixed addresses out of the US release, so anything else is
          // the wrong file and the module rejects it. Saying so at the picker
          // is kinder than saying it after a failed run.
          acceptsModified: false,
        },
        {
          id: "language",
          required: false,
          repeatable: true,
          label: loc(
            "Additional Language",
            "Langue supplémentaire",
            "Zusätzliche Sprache",
          ),
          description: loc(
            "Supplies that language's dialogue and font.",
            "Fournit les dialogues et la police de cette langue.",
            "Liefert Dialoge und Schrift dieser Sprache.",
          ),
          extensions: [".sfc", ".smc"],
          maxBytes: 8 * 1024 * 1024,
          // The hashes and the language codes are the same table the Python
          // uses (tables/util.py, ZELDA3_SHA1). Two different releases both
          // carry the "redux" code, so the ids below disambiguate them while
          // `language` stays the code the converter uses.
          variants: [
            {
              id: "de",
              language: "de",
              label: loc("German", "Allemand", "Deutsch"),
              sha1: "2E62494967FB0AFDF5DA1635607F9641DF7C6559",
            },
            {
              id: "fr",
              language: "fr",
              label: loc("French", "Français", "Französisch"),
              sha1: "229364A1B92A05167CD38609B1AA98F7041987CC",
            },
            {
              id: "fr-c",
              language: "fr-c",
              label: loc("French (Canada)", "Français (Canada)", "Französisch (Kanada)"),
              sha1: "C1C6C7F76FFF936C534FF11F87A54162FC0AA100",
            },
            {
              id: "en",
              language: "en",
              label: loc("English (Europe)", "Anglais (Europe)", "Englisch (Europa)"),
              sha1: "7C073A222569B9B8E8CA5FCB5DFEC3B5E31DA895",
            },
            {
              id: "es",
              language: "es",
              label: loc(
                "Spanish (fan)", "Espagnol (fan)", "Spanisch (Fan)",
              ),
              url: "https://www.romhacking.net/translations/2195/",
              sha1: "461FCBD700D1332009C0E85A7A136E2A8E4B111E",
            },
            {
              id: "pl",
              language: "pl",
              label: loc(
                "Polish (fan)", "Polonais (fan)", "Polnisch (Fan)",
              ),
              url: "https://www.romhacking.net/translations/5760/",
              sha1: "3C4D605EEFDA1D76F101965138F238476655B11D",
            },
            {
              id: "pt",
              language: "pt",
              label: loc(
                "Portuguese (fan)", "Portugais (fan)", "Portugiesisch (Fan)",
              ),
              url: "https://www.romhacking.net/translations/6530/",
              sha1: "D0D09ED41F9C373FE6AFDCCAFBF0DA8C88D3D90D",
            },
            {
              id: "redux-translation",
              language: "redux",
              label: loc(
                "English (Redux)", "Anglais (Redux)", "Englisch (Redux)",
              ),
              url: "https://www.romhacking.net/translations/6657/",
              sha1: "B2A07A59E64C498BC1B2F28728F9BF4014C8D582",
            },
            {
              id: "redux-hack",
              language: "redux",
              label: loc(
                "English (Redux, hack)", "Anglais (Redux, hack)", "Englisch (Redux, Hack)",
              ),
              url: "https://www.romhacking.net/hacks/2594/",
              sha1: "9325C22EB0A2A1F0017157C8B620BC3A605CEDE1",
            },
            {
              id: "nl",
              language: "nl",
              label: loc(
                "Dutch (fan)", "Néerlandais (fan)", "Niederländisch (Fan)",
              ),
              url: "https://www.romhacking.net/translations/1124/",
              sha1: "FA8ADFDBA2697C9A54D583A1284A22AC764C7637",
            },
            {
              id: "sv",
              language: "sv",
              label: loc(
                "Swedish (fan)", "Suédois (fan)", "Schwedisch (Fan)",
              ),
              url: "https://www.romhacking.net/translations/982/",
              sha1: "43CD3438469B2C3FE879EA2F410B3EF3CB3F1CA4",
            },
          ],
          acceptsModified: false,
        },
      ],

      outputs: [
        {
          filename: "zelda3_assets.dat",
          label: loc("Asset pack", "Pack de ressources", "Ressourcenpaket"),
          description: loc(
            "Asset pack consumed by the Zelda 3 port.",
            "Le pack de ressources dont le portage de Zelda 3 a besoin.",
            "Das Asset-Paket, das der Port von Zelda 3 benötigt.",
          ),
        },
      ],

      // Hashes of a real run, or null. See the comment above.
      reference,

      limits: {
        maxOutputBytes: 64 * 1024 * 1024,
        // Advisory: lets a host size a Worker timeout. Cancellation is Worker
        // termination -- the ABI has no cancel flag and cannot have one.
        //
        // Measured: a full US conversion is about 55 ms and US + two
        // languages about 120 ms under Node. 1000 is generous headroom for a
        // slow phone without inviting a host to wait a minute on a hang.
        typicalRuntimeMs: 1000,
      },

      flags: { noHashCheck: 1, noIncludeRom: 2 },
    },
  ],
};

writeFileSync(outPath, JSON.stringify(manifest, null, 2) + "\n");
console.log(`wrote ${outPath}`);
console.log(`  sha256 ${manifest.tools[0].module.sha256}`);
console.log(`  reference run: ${reference ? "present" : "absent (no ROM available at build time)"}`);
