
import sys, os
from datetime import datetime, timedelta

from airflow import DAG
from airflow.operators.bash import BashOperator

ARTIFACT_DIR = f"{os.path.dirname(os.path.abspath(__file__))}/../.."

def docker_operator(task_id, bash_command):
    return BashOperator(
        task_id=task_id,
        bash_command=f"echo '{bash_command}' | ~/.cache/scalacli/local-repo/bin/scala-cli/scala-cli {ARTIFACT_DIR}/work-desk/exec.scala -- polytracker"
    )

with DAG(
    'build_libtiff',
    default_args={
        'depends_on_past': False,
        'email': ['airflow@example.com'],
        'email_on_failure': False,
        'email_on_retry': False,
        'retries': 0,
        'retry_delay': timedelta(seconds=300),
        # 'queue': 'bash_queue',
        # 'pool': 'backfill',
        # 'priority_weight': 10,
        # 'end_date': datetime(2016, 1, 1),
        # 'wait_for_downstream': False,
        # 'sla': timedelta(hours=2),
        # 'execution_timeout': timedelta(seconds=300),
        # 'on_failure_callback': some_function,
        # 'on_success_callback': some_other_function,
        # 'on_retry_callback': another_function,
        # 'sla_miss_callback': yet_another_function,
        # 'trigger_rule': 'all_success'
    },
    description='2025/09/07 ACSAC Artifact Evaluation',
    schedule_interval=None,
    start_date=datetime(2021, 1, 1),
    catchup=False,
    tags=['project-ultimate-sanitizer', 'taint-tracking'],
) as dag:

    PROJECT_DIR = ARTIFACT_DIR

    LLVM_DIR = f"{PROJECT_DIR}/llvm-project"
    TRY_CLANG_DIR = f"{PROJECT_DIR}/try-clang"
    MAGMA_DIR = f"{PROJECT_DIR}/magma-v1.2"
    EVALUATION_DIR = f"{PROJECT_DIR}/evaluation"

    CC="clang"
    CXX="clang++"
    CFLAGS = f"\"-w -g -fno-discard-value-names -DMAGMA_ENABLE_CANARIES -include {TRY_CLANG_DIR}/canary.h -Wno-error=int-conversion \""
    CXXFLAGS = CFLAGS
    LDFLAGS = f""
    LIBS = f"\"{MAGMA_DIR}/fuzzers/vanilla/afl_driver.o \""

    target_libtiff = f"{MAGMA_DIR}/targets/libtiff"
    WORKDIR = f"{target_libtiff}/repo"

    task_reset_tracee = BashOperator(
        task_id='reset_tracee',
        bash_command=f'git -C {WORKDIR} reset --hard && git -C {WORKDIR} clean -dfx',
    )

    task_apply_patch = BashOperator(
        task_id='apply_patch',
        bash_command=f'cd {WORKDIR} && TARGET={target_libtiff} {MAGMA_DIR}/magma/apply_patches.sh ',
    )

    task_manual_patch = BashOperator(
        task_id='manual_patch',
        bash_command=f'cd {WORKDIR} && patch -p1 -i {EVALUATION_DIR}/libtiff/libtiff.no-va_arg.patch'
    )

    task_build_vanilla_fuzzer = docker_operator(
        task_id='build_vanilla_fuzzer',
        bash_command=f'cd {WORKDIR} && FUZZER={MAGMA_DIR}/fuzzers/vanilla OUT=${{FUZZER}} CXX={CXX} CXXFLAGS="" {MAGMA_DIR}/fuzzers/vanilla/build.polytracker.sh ',
    )

    task_fetch_sh = BashOperator(
        task_id='fetch_sh',
        bash_command=f'ls {WORKDIR} || TARGET={target_libtiff} OUT={target_libtiff} {target_libtiff}/fetch.sh ',
    )

    task_build_tracee_with_asan = docker_operator(
        task_id='build_tracee_with_asan',
        bash_command=f'CC={CC} CXX={CXX} CFLAGS="-g -fsanitize=address" CXXFLAGS="-g -fsanitize=address" LDFLAGS={LDFLAGS} LIBS={LIBS} TARGET={target_libtiff} OUT={target_libtiff} {target_libtiff}/build.sh && cd {WORKDIR} && cp -v build/tools/tiffcp ../tiffcp.asan ', # 末尾にスペースを入れないと template と判定される
    )

    task_build_tracee = docker_operator(
        task_id='build_tracee',
        bash_command=f'CC={CC} CXX={CXX} CFLAGS={CFLAGS} CXXFLAGS={CXXFLAGS} LDFLAGS={LDFLAGS} LIBS={LIBS} TARGET={target_libtiff} OUT={target_libtiff} {target_libtiff}/build.polytracker.sh ', # 末尾にスペースを入れないと template と判定される
    )

    task_make_clean = BashOperator(
        task_id='make_clean',
        bash_command=f'git -C {WORKDIR} clean -dfx',
    )

    [
        task_fetch_sh >> task_build_vanilla_fuzzer >> task_reset_tracee >> task_apply_patch >> task_manual_patch,
    ] >> task_build_tracee_with_asan >> task_make_clean >> task_build_tracee