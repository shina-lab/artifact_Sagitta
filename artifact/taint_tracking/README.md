


```shell
### Start docker container installed with docker
~/bin/work-desk/shell.scala polytracker

### In the container
./run.sc
### or 
~/.cache/scalacli/local-repo/bin/scala-cli/scala-cli ./run.sc -- test
```


テイントログの確認
```shell
python3 taint_tracking/analyze.py /dev/shm/polytracker.tdag
### or 
./run.sc analyze
```

pre-commit-hook
```
pip install pre-commit
pre-commit install
```