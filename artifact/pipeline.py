import time
import os
import subprocess

# def build_tracee():
#     from airflow.api.client.local_client import Client
#     from airflow.models import DagRun
#     from airflow.utils.db import provide_session

#     @provide_session
#     def get_dag_run_state(dag_id, run_id, session=None):
#         dag_run = session.query(DagRun).filter(
#             DagRun.dag_id == dag_id,
#             DagRun.run_id == run_id
#         ).first()
        
#         if dag_run:
#             print(f"DAG run found: {dag_run}, state: {dag_run.state}")
#             return dag_run.state
#         return None

#     print("[*] Phase 1: Reproduce the bug, and")
#     print("    Phase 2: Build the tracee")
#     print(f"AIRFLOW_HOME: {os.environ['AIRFLOW_HOME']}")

#     DAG_ID = "build_libtiff"
#     client = Client(None, None)

#     running = client.trigger_dag(DAG_ID)
#     run_id = running.get("dag_run_id")
#     print(f"DAG triggered with run_id: {run_id}")

#     while True:
#         state = get_dag_run_state(DAG_ID, run_id)
#         print(f"Current state: {state}")
#         if state in ["success", "failed"]:
#             break
#         time.sleep(10)

#     if state == "success":
#         print("Successfully completed the DAG.")
#     else:
#         print("DAG execution failed.")
#         exit(1)
#     print("[*] Phase 1 & 2: Done")

def build_tracee():
    print("[*] Phase 1: Reproduce the bug, and")
    print("    Phase 2: Build the tracee")
    artifact_dir = os.path.dirname(os.path.abspath(__file__))
    subprocess.run([f"{artifact_dir}/build_libtiff.sh"], check=True)
    pass

def run_analysis():
    def run_in_docker(bash_command, cwd):
        HOME = os.environ["HOME"]
        subprocess.run(
            f"scala-cli {ARTIFACT_DIR}/work-desk/exec.scala -- polytracker.slim",
            cwd=cwd,
            input=bash_command,
            shell=True,
            check=True
        )
    
    print("[*] Phase 2: Run the analysis")
    run_in_docker(b"./run.sc", f"{ARTIFACT_DIR}/evaluation/libtiff-TIF008")
    print("[*] Phase 3: Done")
    
def collect_results():
    import shutil
    from pathlib import Path

    print("[*] Phase 4: Collect the results to start review the localized graph")
    src = Path(f'{ARTIFACT_DIR}/evaluation/libtiff-TIF008/result/diff.TIF008.crash-000117.taint.svg')
    dst_dir = Path(f'{ARTIFACT_DIR}/../claims/claim1')
    dst = dst_dir / src.name
    dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    print(f"[*] Phase 4: Done. Please review generated localized graph: {dst}")

if __name__ == "__main__":
    ARTIFACT_DIR = os.path.dirname(os.path.abspath(__file__))
    os.environ["AIRFLOW_HOME"] = f"{os.path.dirname(os.path.abspath(__file__))}/airflow"

    import argparse
    parser = argparse.ArgumentParser(description='Run the artifact evaluation pipeline.')
    parser.add_argument("--build", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--collect", action="store_true")
    args = parser.parse_args()

    full = not args.build and not args.run and not args.collect

    start_time = time.time()

    if args.build or full:
        build_tracee()
    if args.run or full:
        run_analysis()
    if args.collect or full:
        collect_results()
    
    end_time = time.time()
    print(f"[*] Total execution time: {end_time - start_time:.2f} seconds")