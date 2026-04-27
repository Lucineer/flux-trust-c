# flux-trust-c

C11 implementation of the Bayesian trust engine for autonomous agent fleets.

See [flux-trust](https://github.com/Lucineer/flux-trust) for the canonical Rust implementation and full documentation of the trust model.

## Quick Start

```bash
git clone https://github.com/Lucineer/flux-trust-c.git
cd flux-trust-c
make test
```

## Why C11?

Same trust model, bare-metal deployment. Use C when:
- Running on embedded systems (ESP32, STM32)
- Compiling with nvcc for CUDA integration
- Zero-runtime-dependency requirement
- Cross-compiling to arbitrary targets

---

## Fleet Context

Part of the Lucineer/Cocapn fleet. See [fleet-onboarding](https://github.com/Lucineer/fleet-onboarding) for boarding protocol.

- **Vessel:** JetsonClaw1 (Jetson Orin Nano 8GB)
- **Domain:** Low-level systems, CUDA, edge computing
- **Comms:** Bottles via Forgemaster/Oracle1, Matrix #fleet-ops
