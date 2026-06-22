# result.py
import os, sys, json
from db.mariadb import MariaDB
from sqlalchemy import text


class Result:
    def __init__(self):
        self.total_path = "/root/project"

        # source files
        self.cookies_result_path = os.path.join(self.total_path, "cookies_result.txt")
        self.storage_result_path = os.path.join(self.total_path, "storage_result.txt")
        self.GPT_JS_result_path = os.path.join(self.total_path, "gpt_js_summary.json")
        self.GPT_HTML_result_path = os.path.join(self.total_path, "gpt_html_summary.json")
        self.logic1_result_path = os.path.join(self.total_path, "logic1_result.json")

        # output files
        self.total_txt_result_path = os.path.join(self.total_path, "total_txt_result.txt")
        self.total_json_result_path = os.path.join(self.total_path, "total_json_result.json")

        # DB 연결 객체
        self.db = MariaDB()

    # -------------------------------
    # TXT 병합
    # -------------------------------
    def merge_txt_files(self):
        txt_files = [
            self.cookies_result_path,
            self.storage_result_path
        ]

        with open(self.total_txt_result_path, "w", encoding="utf-8") as out:
            for path in txt_files:
                if not os.path.isfile(path):
                    continue

                with open(path, "r", encoding="utf-8") as f:
                    out.write(f"----- [FILE] {path} -----\n")
                    out.write(f.read())
                    out.write("\n\n")

    # -------------------------------
    # JSON 병합
    # -------------------------------
    def merge_json_files(self):
        json_files = [
            self.GPT_HTML_result_path,
            self.GPT_JS_result_path,
            self.logic1_result_path
        ]

        merged = {}

        for path in json_files:
            if not os.path.isfile(path):
                continue

            with open(path, "r", encoding="utf-8") as f:
                merged[os.path.basename(path)] = json.load(f)

        with open(self.total_json_result_path, "w", encoding="utf-8") as f:
            json.dump(merged, f, ensure_ascii=False, indent=2)



if __name__ == "__main__":

    result = Result()
    result.merge_txt_files()
    result.merge_json_files()
