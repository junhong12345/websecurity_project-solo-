#Logic2 GPT로 웹소스코드분석하는 기능 초안 

import os, re, sys, time, json 

import requests
from openai import OpenAI

class GPTScanner():
    def __init__(self):
        self.content = None
        self.result = ''
        
        self.max_len = 50000
        self.full_code = ''
        self.chunks = ''

        self.client = OpenAI(api_key="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")        #이건 추후에 지우기로 함
        self.model_name = "gpt-4o-mini"
        self.api_key = None
        self.SYSTEM_PROMPT = ("~~~~~")      #프롬프트 입력하기 (추후에 프롬프트 설정해서 넣어주기로 함)

        #path 
        self.total_path = "/root/project"
        self.downloaded_path = os.path.join(self.total_path, "downloaded")
        self.combined_txt_path = os.path.join(self.downloaded_path, "combined.txt")
        self.index_html_path = os.path.join(self.downloaded_path, "index.html")
        self.result_path = os.path.join(self.total_path, "GPT_result.json")

        #api_key
        self.api_key_path = os.path.join(self.total_path, "api_key")
        if not os.path.isfile(self.api_key_path):
            print(f"api키 파일이 존재하지 않습니다.")
            print("프로그램을 종료합니다.")
        elif os.path.isfile(self.api_key_path):
            print(f"api키 파일이 확인되었습니다.")
            with open(self.api_key_path, "r", encoding="utf-8") as f:
                self.api_key = f.read()
                print("api_key 저장 완료")

    def openfile(self):
        if os.path.exists(self.combined_txt_path) and os.path.isfile(self.combined_txt_path):
            try:
                with open(self.combined_txt_path, "r", encoding='utf-8') as f:
                    self.content = f.read()
                    print(f"{self.combined_txt_path}파일 불러오기 성공")
            except Exception as e:
                print(f"ERROR: {e}")

        elif not os.path.isfile(self.combined_txt_path):
            print(f"{self.combined_txt_path}파일이 존재하지 않습니다.")
            print("프로그램을 종료합니다.\n")
            sys.exit(1)

    def analyze_file(self): 
        system_prompt = self.SYSTEM_PROMPT
        try:
            '''gpt scanner 코드 인용해서 작성하기 '''

        except Exception as e:
            print(f"ERROR: {e}")


    def save_result(self):
        if os.path.isfile(self.result):
            print(f"{self.result}파일이 존재합니다.\n")
            try:
                with open(self.result_path, "w", encoding="utf-8") as f:
                    json.dump(self.result, f, ensure_ascii = False ,indent =2)
                    print(f"{self.result_path} 경로로 파일 생성 완료")
            except Exception as e:
                print(f"ERROR: {e}")

        elif not os.path.isfile(self.result):
            print(f"{self.result}가 존재하지 않습니다.")
            sys.exit(1)

    def read_result(self):
        print(self.result)

    