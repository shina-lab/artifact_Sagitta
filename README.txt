=== Artifact of Sagitta

This artifact contains source code for Section 6 of our paper.

Dependencies: Ubuntu 22.04, Docker (accessible from a regular user), an x86_64 machine, and sudo.
Infrastructure: Standard x86_64 machine (no special devices required).
Machine Spec: Recommend 4 CPUs, 32GB RAM, 100GB Storage.
Expected runtime: 40 minutes (installation 15 minutes + claim 25 minutes).
Repository: https://github.com/shina-lab/artifact_Sagitta
To reproduce Claim 1: run install.sh, then claims/claim1/run.sh, and follow claims/claim1/expected/validation_info.txt.
Expected output and validation information are in claims/claim1/expected/.


--- List of source code and input/output files
This section maps the artifact structure to the corresponding sections in our paper.

Software components (source code): 
    artifact/evaluation
        Analysis pipeline tailored for our tool (Section 6.3)
        Contains evaluated cases (e.g., TIF008 used for Claim 1) with run.sc scripts
    artifact/magma-v1.2 
        Modified Magma framework (Section 6.1)
    artifact/polytracker
        Modified PolyTracker for taint analysis (Section 5)
    artifact/taint_tracking
        Our localization graph tool implementation (Section 5)
    artifact/try-clang
        Supplemental headers for Magma compilation
    artifact/work-desk
        Build and runtime environments for PolyTracker and our tool
    artifact/build_libtiff.sh
        LibTIFF compilation script (used in Claim 1)
    artifact/pipeline.py
        Tool execution script (used in Claim 1)

Input pair (Section 6.1): 
    evaluation/input-file/
        Directories contain crash/non-crash inputs
        Input pair is selected by run.sc scripts in artifact/evaluation/


--- Common issues
- If no SVG file is generated: Check that phase 1-3 completed without errors.
- If nodes are hard to find: Use browser zoom-in/out for better visibility.
- If run.sh fails: Check disk space.
