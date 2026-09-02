# ETP identity and writing

This file defines the public identity for Effect Transaction Protocol. It
applies to the website, repository graphics, diagrams, and project copy.

## Audience and page task

The primary audience is engineers who build agent runtimes, authorization
services, execution systems, and infrastructure controls. A public ETP page
must let a reader answer these questions quickly:

1. What does ETP specify?
2. Where does it sit in an execution path?
3. Which properties does the repository check?
4. Which properties remain deployment responsibilities?

## Mark

The primary mark is [`assets/etp-mark.svg`](./assets/etp-mark.svg). It is a
grant record with one piece removed from its dispatch edge. The removed piece
represents the single attempt created when an executor claims a grant.

The mark refers to the protocol transition from `UNUSED` to `CONSUMED`. It does
not represent a lock, shield, chain, or certification seal.

Construction uses a 24 by 24 unit grid:

- grant body: 14 by 14 units;
- center notch: 4 by 6 units;
- attempt piece: 4 by 4 units;
- gap between body and attempt: 2 units.

Use the two-color mark on light backgrounds. Use
[`assets/etp-mark-mono.svg`](./assets/etp-mark-mono.svg) when only one color is
available. Keep clear space equal to the attempt piece on every side. Do not
round, rotate, outline, repeat, or animate the mark.

[`assets/etp-linearization.svg`](./assets/etp-linearization.svg) is a secondary
technical notation. It shows `UNUSED`, the atomic claim boundary, and
`CONSUMED`. Do not use it as the primary logo.

## Color

| Token | Value | Use |
| --- | --- | --- |
| ink | `#121715` | Primary text and the grant body |
| paper | `#F4F7F5` | Page background |
| line | `#C8D1CD` | Rules and structural boundaries |
| muted | `#52605A` | Secondary text |
| confirmed | `#0B6B57` | Allowed or confirmed state |
| unknown | `#A45F00` | Unknown outcome |
| rejected | `#A33A2B` | Denied or invalid state |

State colors always carry the meanings in this table. Do not use them as
decoration.

## Type

Use IBM Plex Sans for headings and prose. Use IBM Plex Mono for protocol
identifiers, field values, versions, and evidence labels. The repository
vendors only the required web-font files. Their license is in
[`assets/fonts/OFL.txt`](./assets/fonts/OFL.txt).

## Writing

Describe the protocol before making a claim about its value. Use the record
names and state names from [`LANGUAGE.md`](./LANGUAGE.md). Prefer a concrete
example over a slogan.

Interface and website copy must follow these rules:

1. Start headings with the subject or action.
2. Use active voice when the actor is known.
3. Give one control one stable action name.
4. State an evidence boundary next to each count or formal result.
5. Name the repository or deployment when a claim does not apply to ETP in
   general.
6. Remove filler introductions and conclusions.
7. Do not force ideas into groups of three.
8. Do not use contrast formulas such as "not X but Y".
9. Do not call the project secure, verified, standard, or production ready
   without the evidence required by [`LANGUAGE.md`](./LANGUAGE.md).

The preferred short description is:

> ETP defines records and executor rules for external actions proposed by
> untrusted agents, from authorization through outcome reconciliation.

## Asset sources

- `assets/social-card.svg` is the editable source for the social preview.
- `assets/social-card.png` is the rendered 1280 by 640 image.
- `assets/apple-touch-icon.svg` is the editable source for the touch icon.
- `assets/apple-touch-icon.png` is the rendered 180 by 180 image.

Regenerate raster assets from their matching SVG source. Do not edit the
raster copy independently.
