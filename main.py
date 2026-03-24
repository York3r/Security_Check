from core import (
    resolve_domain_to_ip, validate_ip, get_ip_info, scan_ports,
    analyze_ssl, analyze_http_headers, calculate_security_score,
    get_expert_conclusion, print_report
)


def main():
    print("========================================")
    print("  АНАЛИЗАТОР БЕЗОПАСНОСТИ ПРЕДПРИЯТИЯ")
    print("========================================")

    user_input = input("\nВведите IP-адрес или доменное имя: ").strip()

    if validate_ip(user_input):
        ip = user_input
        hostname = ip
    else:
        ip = resolve_domain_to_ip(user_input)
        hostname = user_input
        if not ip:
            print(f"Ошибка: не удалось разрешить '{user_input}' в IP-адрес")
            return

    print(f"\nЦелевой IP: {ip}")
    print("Выполняется анализ, пожалуйста, подождите...\n")

    info = get_ip_info(ip)
    open_ports = scan_ports(ip)
    print(f"  Обнаружено открытых портов: {len(open_ports)}")

    ssl_info = analyze_ssl(hostname) if any(p["port"] == 443 for p in open_ports) else {"has_ssl": False}
    http_headers = analyze_http_headers(hostname) if any(p["port"] in [80, 443] for p in open_ports) else {}

    score, risk_factors, _ = calculate_security_score(info, open_ports, ssl_info, http_headers)
    level, conclusion, recommendations, rating, stars = get_expert_conclusion(score, open_ports, ssl_info)

    print_report(ip, hostname, info, open_ports, ssl_info, http_headers,
                 score, risk_factors, level, conclusion, recommendations, rating, stars)


if __name__ == "__main__":
    main()