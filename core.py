import socket
import ssl
import ipaddress
import concurrent.futures
import math
from datetime import datetime
import requests
import urllib3
from config import (
    PORTS_CONFIG, CRITICAL_PORTS, HTTP_HEADERS, CRITICAL_HEADERS,
    ADMIN_PORTS, HOSTING_KEYWORDS, RISK_LEVELS, FORMULA_COEFFS,
    SECURITY_LEVELS, SPECIFIC_RECOMMENDATIONS,
    USE_COLORS, SYMBOL_PRESENT, SYMBOL_MISSING, SYMBOL_UNKNOWN,
    SYMBOL_GOOD, SYMBOL_WARNING, SYMBOL_CRITICAL
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================
def get_risk_level(risk_value):
    """Возвращает уровень опасности по числовому значению"""
    if risk_value >= RISK_LEVELS["critical"]:
        return "КРИТИЧЕСКИЙ"
    elif risk_value >= RISK_LEVELS["high"]:
        return "ВЫСОКИЙ"
    elif risk_value >= RISK_LEVELS["medium"]:
        return "СРЕДНИЙ"
    else:
        return "НИЗКИЙ"


def get_security_level(score):
    """Возвращает уровень безопасности по баллу"""
    for level in SECURITY_LEVELS:
        if score >= level["min"]:
            return level
    return SECURITY_LEVELS[-1]


def format_rating(stars):
    """Форматирует рейтинг звёздами (без спецсимволов)"""
    return f"{stars}/5"


# ==================== IP И DNS ====================
def resolve_domain_to_ip(hostname):
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for addr in addrs:
            ip = addr[4][0]
            if not ip.startswith(('127.', '192.168.', '10.', '172.16.', '198.18.')):
                return ip
        return addrs[0][4][0] if addrs else None
    except socket.gaierror:
        return None


def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_ip_type(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return "Частный (внутренний)"
        elif ip_obj.is_global:
            return "Публичный (внешний)"
        return "Специальный"
    except:
        return "Не определён"


def get_ip_info(ip: str) -> dict:
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = response.json()
        if data.get("status") == "success":
            return data
        return {}
    except Exception:
        return {}


def detect_hosting(info: dict) -> tuple:
    isp = str(info.get("isp", "")).lower()
    org = str(info.get("org", "")).lower()
    combined = f"{isp} {org}"

    for keyword in HOSTING_KEYWORDS:
        if keyword in combined:
            return 1, "Обнаружены признаки облачной или хостинговой инфраструктуры"
    return 0, "Признаки облачной или хостинговой инфраструктуры не выявлены"


def detect_admin_services(open_ports: list) -> tuple:
    ports = {item["port"] for item in open_ports}
    found_admin = sorted(list(ports & ADMIN_PORTS))

    if found_admin:
        return 1, f"Обнаружены административные сервисы: {found_admin}"
    return 0, "Административные сервисы извне не обнаружены"


# ==================== СКАНИРОВАНИЕ ПОРТОВ ====================
def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.5)
    try:
        result = sock.connect_ex((ip, port))
        if result == 0:
            try:
                sock.settimeout(2)
                sock.send(b'\r\n')
                banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
            except:
                banner = ""

            sock.close()

            if port in PORTS_CONFIG:
                name, risk, comment = PORTS_CONFIG[port]
                return {
                    "port": port,
                    "service": name,
                    "risk": risk,
                    "comment": comment,
                    "banner": banner[:100],
                    "critical": port in CRITICAL_PORTS
                }
            return {
                "port": port,
                "service": "Unknown",
                "risk": 8,
                "comment": "Неизвестный сервис",
                "banner": banner[:100],
                "critical": False
            }
    except:
        pass
    finally:
        sock.close()
    return None


def scan_ports(ip):
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in PORTS_CONFIG.keys()}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    if len(open_ports) > 10:
        has_web = any(p["port"] in [80, 443] for p in open_ports)
        if has_web:
            try:
                r = requests.get(f"https://{ip}", timeout=3, verify=False)
                if r.status_code < 500:
                    open_ports = [p for p in open_ports if p["port"] in [22, 80, 443]]
            except:
                pass

    return sorted(open_ports, key=lambda x: x["port"])


# ==================== SSL/TLS ====================
def analyze_ssl(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "has_ssl": True,
                    "version": ssock.version(),
                    "expiry": cert.get("notAfter"),
                    "subject": dict(x[0] for x in cert.get("subject", [])).get("commonName", "N/A"),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "N/A")
                }
    except:
        return {"has_ssl": False}


# ==================== HTTP ЗАГОЛОВКИ ====================
def analyze_http_headers(hostname):
    results = {}
    for protocol in ["https", "http"]:
        try:
            response = requests.get(f"{protocol}://{hostname}", timeout=5, verify=False)
            for header in HTTP_HEADERS:
                results[header] = "Присутствует" if header in response.headers else "Отсутствует"
            return results
        except:
            continue
    return {h: "Недоступно" for h in HTTP_HEADERS}


# ==================== РАСЧЁТ ИНДЕКСА ====================
def calculate_security_score(info: dict, open_ports: list, ssl_info: dict, http_headers: dict) -> tuple:
    coeff = FORMULA_COEFFS

    P = sum(p["risk"] for p in open_ports)
    S = len(open_ports)
    H, hosting_comment = detect_hosting(info)
    A, admin_comment = detect_admin_services(open_ports)

    raw_penalty = (coeff["risk_log"] * math.log(1 + P) +
                   coeff["services_sqrt"] * math.sqrt(S) +
                   coeff["hosting"] * H +
                   coeff["admin"] * A)

    ssl_penalty = 0
    has_web = any(p["port"] in [80, 443] for p in open_ports)
    if has_web:
        if not ssl_info.get("has_ssl"):
            ssl_penalty = coeff["ssl_no"]
        else:
            version = ssl_info.get("version", "")
            if not ("TLSv1.3" in version or "TLSv1.2" in version):
                ssl_penalty = coeff["ssl_old"]

    headers_penalty = 0
    if http_headers:
        missing_critical = sum(1 for h in CRITICAL_HEADERS if http_headers.get(h) == "Отсутствует")
        headers_penalty += missing_critical * coeff["header_critical"]
        missing_others = sum(1 for h, v in http_headers.items()
                             if v == "Отсутствует" and h not in CRITICAL_HEADERS)
        headers_penalty += missing_others * coeff["header_other"]

    bonus = 0
    if ssl_info.get("has_ssl") and "TLSv1.3" in ssl_info.get("version", ""):
        bonus += coeff["bonus_tls13"]
    if http_headers.get("Strict-Transport-Security") == "Присутствует":
        bonus += coeff["bonus_hsts"]

    total_penalty = raw_penalty + ssl_penalty + headers_penalty - bonus
    final_score = max(0, min(100, round(100 - total_penalty, 2)))

    risk_factors = [
        ["Суммарный риск портов (P)", f"{P}", f"Сумма рисков всех открытых портов: {P}"],
        ["Количество сервисов (S)", f"{S}", f"Обнаружено открытых сервисов: {S}"],
        ["Хостинговая инфраструктура (H)", f"{H}", hosting_comment],
        ["Административные сервисы (A)", f"{A}", admin_comment],
        ["SSL/TLS штраф", f"{ssl_penalty:.1f}", "Штраф за отсутствие или слабый SSL"],
        ["HTTP заголовки штраф", f"{headers_penalty:.1f}", "Штраф за отсутствие заголовков безопасности"],
        ["Бонус за конфигурацию", f"+{bonus}", "Бонус за хорошую настройку"],
        ["Базовое снижение", f"{raw_penalty:.2f}",
         f"{coeff['risk_log']}*ln(1+P) + {coeff['services_sqrt']}*sqrt(S) + {coeff['hosting']}*H + {coeff['admin']}*A"],
        ["Итоговое снижение", f"{total_penalty:.2f}", "Суммарный штраф"],
        ["Итоговый балл", f"{final_score}", "100 - итоговое снижение"]
    ]

    return final_score, risk_factors, {
        "P": P, "S": S, "H": H, "A": A,
        "ssl_penalty": ssl_penalty,
        "headers_penalty": headers_penalty,
        "bonus": bonus,
        "raw_penalty": raw_penalty,
        "total_penalty": total_penalty
    }


# ==================== ЭКСПЕРТНОЕ ЗАКЛЮЧЕНИЕ ====================
def get_expert_conclusion(score, open_ports, ssl_info):
    level_data = get_security_level(score)

    recommendations = level_data["recommendations"].copy()

    if any(p["port"] == 23 for p in open_ports):
        recommendations.append(SPECIFIC_RECOMMENDATIONS["telnet"])
    if any(p["port"] in [3306, 5432, 6379, 27017] for p in open_ports):
        recommendations.append(SPECIFIC_RECOMMENDATIONS["database"])
    if not ssl_info.get("has_ssl") and any(p["port"] == 80 for p in open_ports):
        recommendations.append(SPECIFIC_RECOMMENDATIONS["no_ssl"])

    return level_data["name"], level_data["conclusion"], recommendations, level_data["rating"], level_data["stars"]


# ==================== ВЫВОД ТАБЛИЦ ====================
def print_report(ip, hostname, info, open_ports, ssl_info, http_headers, score, risk_factors, level, conclusion,
                 recommendations, rating, stars):
    separator = "=" * 80
    line = "-" * 80

    print(f"\n{separator}")
    print("ИНФОРМАЦИОННО-АНАЛИТИЧЕСКАЯ СИСТЕМА ОЦЕНКИ БЕЗОПАСНОСТИ ПРЕДПРИЯТИЯ")
    print(separator)

    # Таблица 1
    print(f"\n[1] Исходные характеристики IP-адреса")
    print(line)
    print(f"  IP-адрес:        {ip}")
    print(f"  Доменное имя:    {hostname if hostname != ip else '—'}")
    print(f"  Тип IP:          {get_ip_type(ip)}")
    print(f"  Страна:          {info.get('country', 'Не определено')}")
    print(f"  Город:           {info.get('city', 'Не определено')}")
    print(f"  Провайдер:       {info.get('isp', 'Не определено')}")
    print(f"  ASN:             {info.get('as', 'Не определено')}")
    print(f"  Дата анализа:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Таблица 2
    print(f"\n[2] Результаты проверки сервисов и портов")
    print(line)
    if open_ports:
        print(f"  {'Порт':<8} | {'Сервис':<14} | {'Уровень':<12} | {'Риск':<6} | Комментарий")
        print(f"  {line}")
        for p in open_ports:
            risk_level = get_risk_level(p["risk"])
            print(f"  {p['port']:<8} | {p['service']:<14} | {risk_level:<12} | {p['risk']:<6} | {p['comment']}")
    else:
        print("  Открытые порты из проверяемого набора не обнаружены.")

    # Таблица 3
    print(f"\n[3] SSL/TLS анализ")
    print(line)
    if ssl_info.get("has_ssl"):
        print(f"  Версия:          {ssl_info.get('version', 'N/A')}")
        print(f"  Сертификат CN:   {ssl_info.get('subject', 'N/A')}")
        print(f"  Эмитент:         {ssl_info.get('issuer', 'N/A')}")
        print(f"  Действителен до: {ssl_info.get('expiry', 'N/A')}")
    else:
        print("  SSL/TLS не используется или недоступен")

    # Таблица 4
    print(f"\n[4] HTTP заголовки безопасности")
    print(line)
    if http_headers:
        for h, v in http_headers.items():
            if v == "Присутствует":
                status = SYMBOL_PRESENT
            elif v == "Отсутствует":
                status = SYMBOL_MISSING
            else:
                status = SYMBOL_UNKNOWN
            print(f"  {h:<45} | {status} {v}")
    else:
        print("  HTTP-анализ недоступен (веб-сервис не обнаружен)")

    # Таблица 5
    print(f"\n[5] Факторы риска")
    print(line)
    print(f"  {'Фактор':<38} | {'Значение':<12} | Комментарий")
    print(f"  {line}")
    for factor in risk_factors:
        print(f"  {factor[0]:<38} | {factor[1]:<12} | {factor[2]}")

    # Таблица 6
    print(f"\n[6] Итоговая оценка безопасности")
    print(line)
    print(f"  Критерий Kиб (ИИБ):     {score} / 100")
    print(f"  Рейтинг:                {rating} ({format_rating(stars)})")
    print(f"  Уровень безопасности:   {level}")

    print(f"\n{separator}")
    print("ЭКСПЕРТНОЕ ЗАКЛЮЧЕНИЕ")
    print(separator)
    print(f"  {conclusion}")

    print(f"\nРЕКОМЕНДАЦИИ ПО ПОВЫШЕНИЮ ЗАЩИЩЁННОСТИ:")
    for idx, rec in enumerate(recommendations, start=1):
        print(f"  {idx}. {rec}")

    print(f"\n{separator}")