#logic4 세션, 쿠키, 로컬 스토리지, 세션스토리지 들을 가져와서 분석하는 기능 

import os, re, sys, time, json


class Logic4:
    def __init__(self):
        self.content = None
        self.result = []

        self.SENSITIVE = re.compile(        #정규표현식 민감정보 
    r"("
    r"password|pass(word)?|pwd|passwd|"
    r"token|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"jwt|bearer|authorization|auth|"
    r"secret|api[_-]?key|private[_-]?key|public[_-]?key|"
    r"session|sessid|jsessionid|phpsessid|"
    r"csrf|xsrf|nonce|"
    r"otp|2fa|mfa|"
    r"email|e[-_]?mail|"
    r"user(name)?|account|acct|login|userid|"
    r"credential|creds|"
    r"oauth|sso"
    r"|"
    r"(token|key|secret)[\"']?\s*[:=]"
    r")",
    re.I
)

        self.storage = {"localStorage": {}, "sessionStorage": {}}
        self.risks = []
        self.storage_risks = []
        

        #path
        self.total_path = "/root/project"
        self.downloaded_path = os.path.join(self.total_path, "downloaded")
        self.cookies_path = os.path.join(self.downloaded_path, "cookies.json")
        self.storage_path = os.path.join(self.downloaded_path, "storage.json")
        
        #result path
        self.cookies_analyze_file = os.path.join(self.total_path, "cookies_result.txt")
        self.storage_analyze_file = os.path.join(self.total_path, "storage_result.txt")    

    def delete_result_file(self):
        for a in (self.cookies_analyze_file, self.storage_analyze_file):
            if os.path.isfile(a):
                try:
                    print("이전 결과 파일이 존재합니다. ")
                    os.remove(a)
                    print(f" {a} 이전 결과 파일 삭제 완료 \n")
                except Exception as e:
                    print(f"ERROR: {e}")

    def open_cookies_file(self):
        if os.path.isfile(self.cookies_path):
                print(f"{self.cookies_path} 파일이 존재합니다.")
                try:
                    with open(self.cookies_path, "r", encoding="utf-8") as f:
                        date = json.load(f)
                    self.cookies = date.get("cookies", [])
                    self.risks = []
                except Exception as e:
                    print(f"ERROR: {e}")
        else:
            print(f"{self.cookies_path}파일이 존재하지 않습니다.")
            print("Logic4 기능을 종료합니다.")
            sys.exit(1)

    def analyze_cookies_file(self):
        for c in self.cookies:
            name = c.get("name")
            httpOnly = c.get("httpOnly")
            secure = c.get("secure")
            sameSite = c.get("sameSite", "")

            if not secure:
                self.risks.append(f"[SIGNAL] 쿠키 '{name}' Secure 속성 미설정")
            
            if not httpOnly:
                self.risks.append(f"[SIGNAL] 쿠키 '{name}' HttpOnly 속성 미설정")

            if sameSite.lower() not in ("lax", "strict", "none"):
                self.risks.append(f"[SIGNAL] 쿠키 '{name}' SameSite 속성 미설정")

            if self.SENSITIVE.search(name) or self.SENSITIVE.search(c.get("value","")):
                self.risks.append(f"[SIGNAL] 쿠키 '{name}' 이름 또는 값에서 민감 키워드 패턴 탐지")

        return self.risks   #return 시키지 말고 그냥 출력 혹은 저장으로 변경해도 괜찮을듯 일단 이대로 유지하기 
    
    def open_storage_file(self):
        if os.path.isfile(self.storage_path):
            print(f"{self.storage_path} 파일이 존재합니다.")
            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    self.storage = json.load(f)
                self.storage_risks = []
            except Exception as e:
                print(f"ERROR: {e}")
        else:
            print(f"{self.storage_path}파일이 존재하지 않습니다.")
            print("Logic4 기능을 종료합니다.")
            sys.exit(1)

    def analyze_storage_file(self):
        try:
            for storage_type in ("localStorage", "sessionStorage"):
                store = self.storage.get(storage_type, {})

                # store 가 dict 가 아니면 (예: [])
                if not isinstance(store, dict):
                    continue

                for key, val in store.items():
                    key_str = str(key)
                    val_str = str(val)

                    if self.SENSITIVE.search(key_str) or self.SENSITIVE.search(val_str):
                        self.storage_risks.append(
                            f"[SIGNAL] {storage_type} 항목에서 민감 키워드 패턴 탐지 → key={key}"
                        )
        except Exception as e:
            print(f"ERROR: {e}")

    def save_cookies_result(self):
        if self.risks:
            try:
                with open(self.cookies_analyze_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(self.risks))
                    print(f"{self.cookies_analyze_file} 쿠키 분석 결과 파일 저장 성공 \n")
            except Exception as e:
                print(f"ERROR: {e}")
        else:
            print("쿠키 분석 결과 파일을 저장하지 못했습니다.")
            
    def save_storage_result(self):
        if self.storage_risks:
            try:
                with open(self.storage_analyze_file, "w", encoding="utf-8") as f:
                    f.write("\n".join(self.storage_risks))
                    print(f"{self.storage_analyze_file} 스토리지 분석 결과 파일 저장 성공\n")

            except Exception as e:
                print(f"ERROR: {e}")

        else:
            print("스토리지 분석 결과 파일을 저장하지 못했습니다.")
    
    def open_result_file(self):
        if os.path.isfile(self.cookies_analyze_file):
            try:
                print(f"{self.cookies_analyze_file}파일 출력: \n")
                with open(self.cookies_analyze_file, "r", encoding = 'utf-8') as f:
                    cookies_result = f.read()
                    print(cookies_result)
            except Exception as e:
                print(f"ERROR: {e}")
        else:
            print("-------------------------------------------")
            print("쿠키 분석 결과 파일이 없기 때문에 출력할 수 없습니다.")

        if os.path.isfile(self.storage_analyze_file):
            try:
                print(f"{self.storage_analyze_file} 파일 출력: \n")
                with open(self.storage_analyze_file, "r", encoding = 'utf-8') as f:
                    storage_result = f.read()
                    print(storage_result)
            except Exception as e:
                print(f"ERROR: {e}")
        else:
            print("-------------------------------------------")
            print("스토리지 분석 결과 파일이 없기 때문에 출력할 수 없습니다.")

if __name__ =="__main__":
    L4 = Logic4()
    L4.delete_result_file()
    L4.open_cookies_file()
    L4.analyze_cookies_file()
    L4.open_storage_file()
    L4.analyze_storage_file()
    L4.save_cookies_result()
    L4.save_storage_result()
    L4.open_result_file()