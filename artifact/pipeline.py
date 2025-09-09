import time
import os
import subprocess

def build_tracee():
    from airflow.api.client.local_client import Client
    from airflow.models import DagRun
    from airflow.utils.db import provide_session

    @provide_session
    def get_dag_run_state(dag_id, run_id, session=None):
        """DAG Runの状態を取得"""
        dag_run = session.query(DagRun).filter(
            DagRun.dag_id == dag_id,
            DagRun.run_id == run_id
        ).first()
        
        if dag_run:
            return dag_run.state
        return None

    print(os.environ["AIRFLOW_HOME"])
    DAG_ID = "build_libtiff"
    client = Client(None, None)

    # DAGをtrigger（実行）
    running = client.trigger_dag(DAG_ID)
    run_id = running.get("dag_run_id")
    print(f"DAG triggered with run_id: {run_id}")


    # 状態ポーリング（定期的にDAG実行状態を確認）
    while True:
        # 個々のDAG Runの状態を取得する（必要ならrun_idも指定）
        state = get_dag_run_state(DAG_ID, run_id)
        print(f"Current state: {state}")
        if state in ["success", "failed"]:
            break
        time.sleep(10)  # 10秒間隔で状態チェック

    if state == "success":
        print("DAGの実行が正常に完了しました。")
    else:
        print("DAGの実行が失敗しました。")
        exit(1)

def run_analysis():
    def run_in_docker(bash_command, cwd):
        HOME = os.environ["HOME"]
        subprocess.run(
            f"{HOME}/.cache/scalacli/local-repo/bin/scala-cli/scala-cli {ARTIFACT_DIR}/work-desk/exec.scala -- polytracker.slim",
            cwd=cwd,
            input=bash_command,
            shell=True,
            check=True
        )
    run_in_docker(b"./run.sc", f"{ARTIFACT_DIR}/evaluation/libtiff-TIF008")
    
def collect_results():
    import shutil
    from pathlib import Path

    src = Path(f'{ARTIFACT_DIR}/evaluation/libtiff-TIF008/result/diff.TIF008.crash-000117.taint.svg')
    dst_dir = Path(f'{ARTIFACT_DIR}/../claims/claim1')
    dst = dst_dir / src.name
    dst_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)

if __name__ == "__main__":
    ARTIFACT_DIR = os.path.dirname(os.path.abspath(__file__))
    os.environ["AIRFLOW_HOME"] = f"{os.path.dirname(os.path.abspath(__file__))}/airflow"

    # build_tracee()
    # run_analysis()
    collect_results()