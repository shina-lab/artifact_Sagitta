=== Artifact of Sagitta

This artifact contains source code for Section 6 of our paper.

Dependencies: Ubuntu 22.04, Docker (usable from normal user), x86_64 machine, sudo.
Infrastructure: Standard x86_64 machine (no special devices required; recommend 4 CPUs + 32GB RAM).
Expected runtime: 40 minutes (installation 15 minutes + claim 25 minutes).
Repository: https://github.com/shina-lab/artifact_Sagitta
To reproduce Claim 1: run install.sh then claims/claim1/run.sh.
Expected output is in claims/claim1/expected/.


--- List of source code and input/output files
This explains which folders correspond to source code and data.

Software components (source code): 
    artifact/evaluation
        our analysis pipeline tailored for our tool library (used in section 6.3)
        subfolders contains evaluated cases (e.g. TIF008), and run.sc invokes analysis pipeline.
    artifact/magma-v1.2 
        Magma framework (modified by us in section 6.1)
    artifact/polytracker
        polytracker (modified by us in section 5)
    artifact/taint_tracking
        our tool (implemented in section 5)
    artifact/try-clang
        Supplemental header file for Magma (required for build Magma and target binaries)
    artifact/work-desk
        Helper utility for building/running polytracker
    artifact/build_libtiff.sh
        Script file to build libtiff (used for claim/claim1)
    artifact/pipeline.py
        Script file to run our tool (used for claim/claim1)

Input pair (section 6.1): 
    In evaluation/input-file/, directories contains crash/non-crash inputs.
    Input pair is picked from these directory by run.sc in artifact/evaluation.

