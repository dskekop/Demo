import datetime
import os
import time
import traceback

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException


# ==================================================
# 配置区（只改这里）
# ==================================================

CLOCK_URL = "https://portal.exampletech.com/#/home"
CAS_LOGIN_PREFIX = "https://cas.exampletech.com/cas/login"

USERNAME = "admin"
PASSWORD = "123456"

USERNAME_SELECTOR = (By.XPATH, "//input[@type='text' or @type='tel']")
PASSWORD_SELECTOR = (By.XPATH, "//input[@type='password']")

# 本地日历文件
HOLIDAYS_FILE = "holidays.txt"
WORKDAYS_EXTRA_FILE = "workdays_extra.txt"
BLACKLIST_FILE = "blacklist_dates.txt"

# EdgeDriver 路径（关键）
EDGE_DRIVER_PATH = r"C:\Users\344272\AppData\Local\Programs\Python\Python314\msedgedriver.exe"

# ==================================================


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


# ==================================================
# 本地工作日判断（方案 1）
# ==================================================

def load_date_set(filepath):
    dates = set()
    if not os.path.exists(filepath):
        return dates

    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            dates.add(line)
    return dates


def should_run_clock():
    today = datetime.date.today()
    today_str = today.strftime("%Y-%m-%d")
    weekday = today.weekday()

    log(f"今日日期：{today_str}（星期{weekday + 1}）")

    holidays = load_date_set(HOLIDAYS_FILE)
    workdays_extra = load_date_set(WORKDAYS_EXTRA_FILE)
    blacklist = load_date_set(BLACKLIST_FILE)

    if today_str in blacklist:
        log("命中个人黑名单，不执行打卡")
        return False

    if today_str in workdays_extra:
        log("调休工作日（周末上班），执行打卡")
        return True

    if today_str in holidays:
        log("法定节假日，不执行打卡")
        return False

    if weekday < 5:
        log("普通工作日（周一至周五），执行打卡")
        return True

    log("普通周末，不执行打卡")
    return False


# ==================================================
# Selenium 打卡主流程
# ==================================================

def run_clock():
    log("启动 Edge 浏览器（headless）")

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--no-sandbox")

    service = Service(executable_path=EDGE_DRIVER_PATH)
    driver = webdriver.Edge(service=service, options=options)

    wait = WebDriverWait(driver, 40)

    try:
        log(f"访问打卡页面: {CLOCK_URL}")
        driver.get(CLOCK_URL)
        wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
        log(f"当前 URL: {driver.current_url}")

        if driver.current_url.startswith(CAS_LOGIN_PREFIX):
            log("检测到未登录，进入 CAS 登录流程")

            user_input = wait.until(
                EC.presence_of_element_located(USERNAME_SELECTOR)
            )
            user_input.clear()
            user_input.send_keys(USERNAME)

            pwd_input = wait.until(
                EC.presence_of_element_located(PASSWORD_SELECTOR)
            )
            pwd_input.clear()
            pwd_input.send_keys(PASSWORD)

            log("提交登录")
            pwd_input.send_keys(Keys.ENTER)

            log("等待 CAS 跳转")
            wait.until(lambda d: not d.current_url.startswith(CAS_LOGIN_PREFIX))
            log("登录成功")

            driver.get(CLOCK_URL)
            wait.until(EC.presence_of_element_located((By.TAG_NAME, "body")))
            log("已进入打卡页面")
        else:
            log("已是登录状态")

        btn = wait.until(
            EC.element_to_be_clickable((By.CSS_SELECTOR, "span.avashove"))
        )
        log("已找到打卡入口")

        def get_sign_out_text():
            try:
                items = btn.find_elements(By.CSS_SELECTOR, "div.time div")
                for el in items:
                    t = el.text.strip()
                    if "签出" in t:
                        return t
                return ""
            except:
                return ""

        old_text = get_sign_out_text()
        log(f"点击前签出状态: {old_text}")

        log("点击打卡按钮")
        btn.click()

        log("等待签出时间更新")

        def sign_out_changed(d):
            new_text = get_sign_out_text()
            return new_text and new_text != old_text

        wait.until(sign_out_changed)

        log("打卡完成")
        log(f"点击后签出状态: {get_sign_out_text()}")

    except TimeoutException:
        log("超时：登录或打卡未生效")
        traceback.print_exc()

    except Exception:
        log("程序运行异常")
        traceback.print_exc()

    finally:
        log("关闭浏览器")
        driver.quit()


# ==================================================
# 程序入口
# ==================================================

if __name__ == "__main__":
    log("程序启动")

    if not should_run_clock():
        log("程序结束：今日无需打卡")
        exit(0)

    run_clock()