#삭제 프로그램
import os, re, sys, time, json, shutil
class Delete:
    def __init__(self):
        self.content = None
        self.result = ''

    def delete_file(self):
        total_path = "/root/project"
        downloaded_path =  os.path.join(total_path,  "downloaded")
        Logic1_result_path = os.path.join(total_path, "logic1_result.json")
        GPT_Scanner_result_path = os.path.join(total_path, "gpt_js_result.json")
        GPT_Scanner_summary_result_path = os.path.join(total_path, "gpt_js_summary.json")
        GPT_HTML_Scanner_result_path = os.path.join(total_path, "gpt_html_result.json")
        GPT_HTML_Scanner__summary_result_path = os.path.join(total_path, "gpt_html_summary.json")
        Logic4_cookies_result_path = os.path.join(total_path, "cookies_result.txt")
        Logic4_storage_result_path = os.path.join(total_path, "storage_result.txt")
        Total_JSON_result_path = os.path.join(total_path, "total_json_result.json")
        Total_TXT_result_path =  os.path.join(total_path, "total_txt_result.txt")
        LLM_TXT_result_path = os.path.join(total_path, "LLM_txt_result.txt")
        LLM_JSON_result_path = os.path.join(total_path, "LLM_json_reuslt.json")
        try:
            if os.path.exists(downloaded_path) and os.path.isdir(downloaded_path):
                shutil.rmtree(downloaded_path)
                print(f"{downloaded_path} 파일 삭제 완료\n")
            elif not os.path.exists(downloaded_path) and not os.path.isdir(downloaded_path):
                print(f"{downloaded_path}파일이 존재하지 않습니다.")

        except Exception as e:
            print(f"ERROR: {e}")

        try:
            for a in (Logic1_result_path, GPT_Scanner_result_path, GPT_Scanner_summary_result_path, GPT_HTML_Scanner__summary_result_path, GPT_HTML_Scanner_result_path, Logic4_cookies_result_path, Logic4_storage_result_path, Total_JSON_result_path, Total_TXT_result_path, LLM_JSON_result_path, LLM_TXT_result_path):
                if os.path.isfile(a):
                    os.remove(a)
                    print(f"{a}파일 삭제 완료\n")

                elif not os.path.isfile(a):
                    print(f"{a}파일이 존재하지 않습니다.\n")
        except Exception as e:
            print(f"ERROR: {e}" )

if __name__=="__main__":
    delete = Delete()
    delete.delete_file()