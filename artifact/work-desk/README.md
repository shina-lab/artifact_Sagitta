work-desk
====

Requirements
----
* Docker daemon が起動していて、自分が操作可能であること
* Scala-CLI

```shell
### Dockerイメージをビルド
./setup.sc default

### シェルを起動。どこから起動してもよい。カレントディレクトリは呼び出し元のカレントディレクトリに合わせてくれる
./shell.scala default

### 他のプロジェクトから利用できるように、ローカルリポジトリに配置
scala-cli publish local shell.scala
```