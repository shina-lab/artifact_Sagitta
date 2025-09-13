#!/bin/env python3
import os
import hashlib

def sha1sum(filename):
    """指定したファイルのSHA-1ハッシュを計算する関数"""
    sha1 = hashlib.sha1()
    try:
        with open(filename, 'rb') as f:
            while True:
                data = f.read(65536)  # 64KBずつ読み込む
                if not data:
                    break
                sha1.update(data)
        return sha1.hexdigest()
    except FileNotFoundError:
        return None

def get_sha1sums(directory):
    """指定したディレクトリ内のすべてのファイルのSHA-1ハッシュを計算する関数"""
    sha1_list = {}
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            sha1_hash = sha1sum(filepath)
            if sha1_hash:
                sha1_list[sha1_hash] = filepath
    return sha1_list

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Find same file in DIR1 and DIR2')
    parser.add_argument("DIR1")
    parser.add_argument("DIR2")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    dir1 = get_sha1sums(args.DIR1)
    dir2 = get_sha1sums(args.DIR2)

    same_files = set(dir1.keys()) & set(dir2.keys())
    for sha1_hash in same_files:
        print(f"{dir1[sha1_hash]} == {dir2[sha1_hash]}")
        if args.debug:
            print(f"SHA-1: {sha1_hash}")
