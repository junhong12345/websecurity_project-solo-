import os, json
from db.mariadb import MariaDB
from sqlalchemy import text

class DB:
    def __init__(self):
        self.base = "/root/project"
        self.total_json_result_path = os.path.join(self.base, "LLM_json_reuslt.json")
        self.total_txt_result_path  = os.path.join(self.base, "LLM_txt_result.txt")
        self.db = MariaDB()

    def save_result_to_db(self, target_url: str):
        with open(self.total_json_result_path, "r", encoding="utf-8") as f:
            json_data = json.load(f)

        with open(self.total_txt_result_path, "r", encoding="utf-8") as f:
            text_data = f.read()

        session = self.db.get_session()

        try:
            session.execute(
                text("""
                INSERT INTO analysis_results (target_url, json_result, text_result)
                VALUES (:url, :json_result, :text_result)
                """),
                {
                    "url": target_url,
                    "json_result": json.dumps(json_data, ensure_ascii=False),
                    "text_result": text_data
                }
            )
            session.commit()

        except Exception as e:
            session.rollback()
            raise RuntimeError(f"[DB ERROR] 결과 저장 실패: {e}")

        finally:
            session.close()
