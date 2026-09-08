# paper/

The technical report. This is the authoritative writeup of KRAKEN: the design, the
full component walkthrough, the honest evaluation of where the approach wins and
where it does not, the lineage, and the roadmap. It is longer and more complete than
the root README or anything under `docs/`.

- `kraken_whitepaper.tex`: the source.
- `Kraken-Whitepaper-v0.1.7.pdf`: the built report.
- `figures/`: the generated figures the report includes.

## Building

The report builds with `tectonic`, which fetches its own TeX dependencies:

```bash
tectonic paper/kraken_whitepaper.tex
```

Any modern LaTeX toolchain with the standard packages will also work.
