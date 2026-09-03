# Distribution

Spec version 1. How a consuming web tool finds and fetches a project's
extractor.

## The constraint that shapes this: release assets are not CORS-fetchable

GitHub **release assets cannot be fetched by a browser from another origin.**
Measured, not assumed:

| URL | `access-control-allow-origin` | Usable from a page |
|---|---|---|
| `api.github.com/repos/O/R/releases/latest` | `*` | yes |
| `github.com/O/R/releases/download/TAG/FILE` | *absent* | **no** |
| `github.com/O/R/releases/latest/download/FILE` | *absent* | **no** |
| `api.github.com/repos/O/R/releases/assets/ID` (octet-stream) | *absent* after redirect | **no** |
| `raw.githubusercontent.com/O/R/REF/PATH` | `*` | yes |
| `cdn.jsdelivr.net/gh/O/R@REF/PATH` | `*` | yes |
| `O.github.io/R/PATH` (GitHub Pages) | `*` | yes |

Release downloads redirect to `release-assets.githubusercontent.com`, which
sends no CORS header at all. `curl` gets the bytes; a browser does not. The
release API is fine for *metadata* — it is only the asset bytes that are
blocked.

So "publish the module in GitHub releases and let the web tool pull it" does
not work as stated. It has to be said plainly because it fails only in a
browser, and only cross-origin: every local test passes.

## The model

Distribution is **tied to release tags**, but the bytes a browser reads come
from a `dist` branch rather than from the release attachments, because those
cannot be fetched.

On every `v*` tag, one CI run publishes the same three files to three places:

- the **`dist` branch**, under `<tag>/` and `latest/` — this is the
  machine-readable channel. `raw.githubusercontent.com` and `cdn.jsdelivr.net`
  both serve it with `access-control-allow-origin: *`, and every version stays
  addressable at its tag forever.
- the **GitHub release** — the same bytes plus `SHA256SUMS`, for humans, for
  `curl`, and as the immutable record.
- the **Pages site** — the conversion UI, which reads its extractor from the
  `dist` branch like any other consumer.

A consumer does:

```
GET https://raw.githubusercontent.com/<owner>/<repo>/dist/latest/manifest.json
GET <module url from that manifest, resolved against it>
verify(moduleBytes)                     # never trust the manifest for this
```

Pin to a tag instead of `latest/` by swapping the path segment. jsDelivr serves
the identical paths if a CDN is preferred, at the cost of cache latency.

The manifest carries the module's `sha256` and, when built from a tag, the
release URL — so the Pages copy can be checked against the release copy by
anyone who cares, and a consumer that mirrors the module can prove its mirror
matches.

Nothing about this is centralised: the URL is derived from the project's own
repo, and a project that does not want GitHub Pages can serve the same two
files from anywhere that sends `access-control-allow-origin: *`.

## Ordering

Pages is deployed **after** the job that verifies the module and attaches it to
the release, and only from a tag. A deployed page can therefore never advertise
a module that failed the gate, and never one that is not also in a release.

Pages is additionally deployed when the page's own sources change, since those
are independent of the module.

## Why the page reads from the dist branch

The conversion page could load the module sitting beside it — it is deployed
with one — but a published build reads from `dist/latest/` instead. That makes
the page a genuine consumer: it performs the same cross-origin fetch, hash
check and verification a third-party tool does, so a break in the distribution
path shows up in the page rather than only in someone else's integration.

`build-page.sh` writes the chosen URL into `site/config.json`. Locally it
defaults to the copy beside the page, so development needs no network.

## Targets: what else an install needs, and where every file goes

The manifest's `tools[]` describes what a user's own ROM is converted into.
That is not a whole install. A game also needs files the project compiled: the
binary itself, and whatever read-only blobs sit beside it. Those live in
`targets[]`, one entry per platform the game can be built for:

```
targets[].id            "gnw-retro-go", "sdl-linux-x64", ...
targets[].platform      the device family
targets[].label         {en, fr, de}
targets[].artifacts[]   files NOT derived from the user's ROM
targets[].install[]     the complete set of files a working install needs
```

An artifact carries `filename`, `bytes`, `sha256`, `url`, `destination`,
`kind` (`device-binary` or `device-asset`), `format` (`gwhb`, `raw` or `elf`)
and, when it cannot stand alone, `pairsWith` naming the artifact it must be
installed next to. `install[]` names both the target's artifacts and the
converter's outputs, so a consumer can assemble a card without knowing that
this particular game happens to have an asset pack at all. Each `install[]`
entry says where the file came from with `from`: `"artifact"` for one of this
target's artifacts, or `"tool"` plus the `tool` id for a file the converter
produces.

### `destination` is authoritative. Do not infer a path.

Every output and every artifact carries a `destination`: an absolute path on
the target device, for example `/homebrews/`.

**A consumer MUST copy the file to that path verbatim, and MUST NOT derive a
path from the file's kind, format, name or extension.**

This is stated as a hard rule because the conventions are not consistent even
inside a single firmware project. In
`game-and-watch-retro-go-sd`, the loader header `Core/Inc/retro-go/gwhb.h`
says homebrew binaries live under `/homebrews/*.bin` with their sibling assets
beside them, while other parts of the same tree still speak of
`/roms/homebrew/` (`external/doom/Makefile.common`, and a legacy path
`rg_favorites.c` explicitly keeps supporting). A consumer that guessed
"homebrew, therefore `/roms/homebrew/`" would write a working set of files to
a directory the launcher does not read, and the user would see nothing wrong
except that the game is missing.

So the path is data, published by the project that knows the answer, and it
can change in a later release without every consuming tool needing a patch.
The manifest is still not a trust root: a destination is a placement
instruction, not a security claim, and everything security-relevant is still
re-derived from the bytes.

## Firmware ABI requirements

An artifact whose `format` is `gwhb` runs against a firmware ABI and declares
what it needs:

```
requires: { firmwareAbiVersion, firmwareAbiMinSize }
```

This appears **only** on `gwhb` artifacts. An SDL executable has no firmware
ABI, and neither does a plain sibling blob like a rodata file, so publishing
these numbers for them would invite a consumer to compare values that mean
nothing.

Both numbers are read back out of the packed `gwhb_meta_t` in the binary by the
manifest generator. They are never hand-written, for the same reason the
module's `sha256` is never hand-written: a number typed into a manifest
describes what someone believed, and a number read from the file describes what
is true. Until the binary exists, `sha256` and `requires` are `null` and
`published` is `false`; a consumer must refuse to install an artifact with a
null hash rather than fetch it unchecked.

### The compatibility predicate

Taken verbatim from the firmware's own loader
(`Core/Src/retro-go/rg_emulators.c`, `gwhb_abi_ok()`):

```c
required_abi <= GW_FIRMWARE_ABI_VERSION
    && required_abi_min_size <= g_firmware_abi.size
```

Both comparisons are `<=`, not `==`: a binary built against an older, smaller
ABI runs fine on newer firmware.

**Why two numbers.** The firmware ABI grows append-only, and appending a field
does not bump `GW_FIRMWARE_ABI_VERSION`. Two firmware builds can therefore
report the same version while their `gw_firmware_abi_t` structs are different
sizes. The version alone cannot tell "this firmware predates a field I need"
from "this firmware has it"; the size can. A binary that needs a recently
appended entry states a `firmwareAbiMinSize` large enough to cover it, and
older firmware of the same version is correctly rejected.

**Where the firmware's two values come from.** A consumer reads them out of the
firmware image itself: `gw_firmware_abi_t` is pinned by the linker at
`GW_FIRMWARE_ABI_ADDRESS`, and its first two `u32` words are `version` and
`size`, in that order. A firmware version string is not a substitute. It is not
the ABI version, it does not carry the struct size, and it is not present in
the image in a machine-readable place.

**Warn, do not assert.** `Core/Inc/retro-go/gw_firmware_abi.h` currently says
in plain words that while external cores are in development, fields may still
be removed or reordered without a version bump. The predicate above is
therefore sound for the append-only case it was written for, and optimistic
outside it. A consumer that finds a mismatch should tell the user what it
found and let them proceed, rather than treating equality as proof or a
difference as certain failure.
