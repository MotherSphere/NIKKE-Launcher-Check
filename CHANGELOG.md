# Changelog

## [0.4.1](https://github.com/MotherSphere/NIKKE-Launcher-Check/compare/v0.4.0...v0.4.1) (2026-11-04)


### Fixes

* **scan:** count an agent download only when it finished, and know two more builds ([51926a2](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/51926a2944e6a0c7bd696f5f1691c2475c5f64c0))
* **scan:** read compressed LevelDB tables when looking for the agent state ([8a823d5](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/8a823d59e4d32358173197e64ea0b209650feb32))

## [0.4.0](https://github.com/MotherSphere/NIKKE-Launcher-Check/compare/v0.3.0...v0.4.0) (2026-11-04)


### Features

* **scan:** make the computer scan quick and keep the full scan as an option ([d3c0aab](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/d3c0aab029aecc4c746328207405de6e21bbae4b))


### Fixes

* **scan:** know the fifth payload build and the Oct 23 agent start ([af2db1c](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/af2db1c63d7a16c4be6862c263bb31a13780a977))


### Documentation

* describe the quick scan and the full scan ([9d23022](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/9d23022be86d2b28aad6b38d793897047d09d14f))

## [0.3.0](https://github.com/MotherSphere/NIKKE-Launcher-Check/compare/v0.2.1...v0.3.0) (2026-11-04)


### Features

* **scan:** find more traces of the agent and of its Chrome DLL ([9e9efe2](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/9e9efe242dc7d3a422d9eec4df052674a1803d54))
* **ui:** guide players through what was found and what to do ([a2d5af0](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/a2d5af093c1b60049f548b384ca4aeb815b6526d))
* **ui:** show MotherSphere with a short hint on the start and steps screens ([de42825](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/de428252691fca13b6fd45b8b1fdee10d0c71f54))


### Fixes

* **scan:** rate a log that names only insightjs as a warning ([082d130](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/082d13069b3d2aae045d61c64fea27d7f1013915))
* **ui:** skip OpenGL on Windows so AMD's driver cannot crash the window ([b2eda50](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/b2eda50727702895122334756f76ebc2badcd64d))


### Documentation

* describe the three tabs, the new checks and the report redaction ([257a1c7](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/257a1c7c9578752fafb5cfc5f9b360a1fd56fb8e))
* the Chrome DLL does not need Chrome; add the second IP and the fourth build ([8eda540](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/8eda540c218eee8503973271783540b476c74cda))

## [0.2.1](https://github.com/MotherSphere/NIKKE-Launcher-Check/compare/v0.2.0...v0.2.1) (2026-11-03)


### Fixes

* **report:** date the agent from October 24 and fix the DLL removal order ([1772cfd](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/1772cfde64ca79285a58b4de91bb9d8128f4e24e))


### Documentation

* add vue-bucket.min.js, the October 24 agent starts, payload builds and the Chrome DLL ([8b867b2](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/8b867b205af5ed5aff3fb4200b54d8bc0ce0fc1b))
* note that drives mounted in a folder are not walked on Windows ([f1e0acd](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/f1e0acdee6d0ce11cc30341409b4adf9f1c1f9a8))

## [0.2.0](https://github.com/MotherSphere/NIKKE-Launcher-Check/compare/v0.1.0...v0.2.0) (2026-11-03)


### Features

* **scan:** search the whole computer with no depth limit ([3679171](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/3679171326a048a1b47b4bbc001105c40a35f0f4))


### Fixes

* show the window for any item dropped on the .exe ([cc25533](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/cc25533966f178434224aa1949c00f0542817d3d))


### Documentation

* split the README into a docs/ folder and add screenshots ([5741c61](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/5741c61e422eced55c5774344109d96f688d5ce5))

## 0.1.0 (2026-11-03)


### Features

* add read-only scanner for NIKKE launcher compromise traces ([75e5054](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/75e50544e4123986c1b818bd88c44bfe9f864223))
* **ui:** add a scan screen with live progress, Stop and folder drop ([0a70778](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/0a70778cb28e8921975debd626fca16a7d0d7f78))


### Fixes

* **discovery:** find more profiles and installs, skip network mounts ([0388d40](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/0388d40dc6f798b126c4df45178e642a271beb5b))
* **report:** correct the dates, the file count and the debug.log advice ([054b590](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/054b590f34d8555ad9c56bba833c37a24b4217d5))
* **scan:** tighten detection rules and label log times ([76276c3](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/76276c3d5bd28a73894e8a3b99e000fabdfbc8d7))
* **ui:** show hosts status per domain and drop stale scan results ([8bdc703](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/8bdc703a1bf65c5075067583589060fa71e0b48f))


### Documentation

* add README ([b6abee9](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/b6abee96209813a258e57ce2cd17a787db459f06))
* describe the new checks, discovery rules and download steps ([d1ba5bb](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/d1ba5bb1a02d6889e4fc06d145bbba90659fa4eb))
* describe the new window, the third CDN file and the release files ([9f613f3](https://github.com/MotherSphere/NIKKE-Launcher-Check/commit/9f613f3ce5a3b3eb1655c583a971c829ae2617f2))
