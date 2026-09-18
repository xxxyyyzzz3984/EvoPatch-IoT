# Method registry

This file freezes the method naming used by the unified BusyBox comparison package.

Implemented now:

- `size_stat` -> `SizeStat`
- `shape_stat` -> `ShapeStat`
- `clap` -> `CLAP`
- `issta_2024` -> `ISSTA 2024`
- `gtrans` -> `GTrans`
- `bar_2024` -> `BAR 2024`
- `ammf` -> `AMMF`
- `cybersecurity_2025` -> `Cybersecurity 2025`
- `binary2vec` -> `Binary2vec`
- `array_2025` -> `Array 2025`
- `evopatch_iot` -> `EvoPatch-IoT`
- `vexir2vec_2023` -> `VEXIR2Vec 2023`
- `ex2vec_2025` -> `Ex2Vec 2025`

Current implementation policy:

- Implemented methods are unified stripped-compatible reproductions under one protocol.
- Method IDs are frozen so configs and result tables stay stable across reruns.
