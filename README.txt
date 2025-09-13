This artifact reproduces the localization graph generation experiment described in Section 6.4.2 of our paper and visualized in Figure 5. The artifact consists of software (source code, build scripts, and analysis tools) and sample data (TIF008 crash input and non-crash input pairs).

The artifact demonstrates our software crash root cause analysis technique through four phases: (1) TIF008 bug reproduction using the Magma framework, (2) instrumented libtiff compilation with polytracker for taint analysis, (3) localization graph generation via data flow analysis, and (4) validation of generated localization graph (in SVG format) against the Figure 5 results.

Software components: Source code (Magma/libtiff), build automation scripts, and analysis pipeline.
Dependencies: Ubuntu 22.04 and Docker.
Hardware requirements: .
Output format: SVG (for graphing).

This artifact contains source code for Section 6 of our paper.
Dependencies: Ubuntu 22.04, Docker, x86_64 machine.
Infrastructure: Standard x86_64 machine (no special devices required).
Expected runtime: 45 minutes.
Repository: https://github.com/shina-lab/artifact_Sagitta
Dataset: Bug dataset artifact/magma-v1.2, and input pair evaluation/input-file/7fcf1f3ea2333be518eac93dc8bcfc276272db21.
To reproduce Claim 1: run install.sh then claims/claim1/run.sh.
Expected output is in claims/claim1/expected/.