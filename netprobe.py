import subprocess
import socket
import ipaddress
import platform
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# Tenta importar o Scapy para envio de pacotes ARP na camada 2
try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0  # Silencia logs internos do Scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def ping_host(ip_str, timeout_ms):
    """
    Realiza varredura ICMP (Ping).
    Retorna True se o host responder ao ping, False caso contrário.
    """
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    
    if platform.system().lower() == 'windows':
        cmd = ['ping', param, '1', '-w', str(timeout_ms), ip_str]
    else:
        timeout_sec = max(1, int(timeout_ms / 1000))
        cmd = ['ping', param, '1', '-W', str(timeout_sec), ip_str]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # No Windows, verifica se houve resposta real c/ TTL para evitar falsos positivos
        if platform.system().lower() == 'windows':
            return "ttl=" in result.stdout.lower()
        return result.returncode == 0
    except Exception:
        return False


def arp_probe(ip_str, timeout_sec):
    """
    Envia um pacote ARP Request diretamente para o IP para descobrir se o host
    está ativo (mesmo bloqueando ICMP) e obter seu MAC Address.
    """
    if SCAPY_AVAILABLE:
        try:
            arp_req = ARP(pdst=ip_str)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            pacote = broadcast / arp_req
            answered, _ = srp(pacote, timeout=timeout_sec, verbose=False)
            for _, rcv in answered:
                return rcv.hwsrc.upper()
        except Exception:
            pass

    # Fallback: Consulta a tabela ARP do próprio sistema operacional
    return obter_mac_tabela_arp(ip_str)


def obter_mac_tabela_arp(ip_str):
    """
    Lê a tabela ARP local do sistema (arp -a) para vincular IP e MAC.
    """
    try:
        res = subprocess.run(['arp', '-a', ip_str], capture_output=True, text=True)
        match = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", res.stdout)
        if match:
            return match.group(0).replace('-', ':').upper()
    except Exception:
        pass
    return None


def verificar_dispositivo(ip_str, timeout_ms):
    """
    Combina Ping Scan + ARP Probe para máxima precisão.
    1. Tenta ICMP Ping.
    2. Se responder ao Ping, busca o MAC Address.
    3. Se NÃO responder ao Ping, dispara ARP Probe para contornar bloqueio de Firewall/ICMP.
    """
    timeout_sec = max(0.5, timeout_ms / 1000.0)
    respondeu_ping = ping_host(ip_str, timeout_ms)

    if respondeu_ping:
        mac = arp_probe(ip_str, timeout_sec) or "MAC Não Identificado"
        return {
            'ip': ip_str,
            'status': 'ONLINE',
            'metodo': 'ICMP Ping',
            'mac': mac
        }
    else:
        # Host não respondeu ao Ping; testa via ARP Probe
        mac = arp_probe(ip_str, timeout_sec)
        if mac:
            return {
                'ip': ip_str,
                'status': 'ONLINE (ICMP Bloqueado)',
                'metodo': 'ARP Probe',
                'mac': mac
            }

    return None


def escanear_porta(ip_str, porta, timeout_sec):
    """Testa se uma porta TCP específica está aberta no IP alvo."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout_sec)
            if s.connect_ex((ip_str, porta)) == 0:
                return porta
    except Exception:
        pass
    return None


def escanear_faixa_portas(ip_str, porta_inicial, porta_final, timeout_ms):
    """Varre um intervalo de portas TCP concorrentemente."""
    portas_abertas = []
    timeout_sec = max(0.2, timeout_ms / 1000.0)

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {
            executor.submit(escanear_porta, ip_str, p, timeout_sec): p
            for p in range(porta_inicial, porta_final + 1)
        }
        for future in as_completed(futures):
            porta = future.result()
            if porta is not None:
                portas_abertas.append(porta)

    return sorted(portas_abertas)


def main():
    print("=" * 75)
    print("   NETPROBE WI-FI — Monitoramento por Ping Scan, ARP Probe e Port Scan")
    print("=" * 75)

    if not SCAPY_AVAILABLE:
        print("[!] AVISO: Biblioteca 'scapy' não encontrada. O script usará o cache ARP")
        print("    do sistema. Para ARP Probe ativo, instale com: pip install scapy\n")

    # 1. Parâmetros de Entrada com valores padrão caso o usuário pressione Enter
    rede_input = input("Digite a faixa de rede /24 [Padrão: 192.168.1.0/24]: ").strip()
    if not rede_input:
        rede_input = "192.168.1.0/24"

    try:
        rede = ipaddress.ip_network(rede_input, strict=False)
    except ValueError as e:
        print(f"[ERRO] Faixa de rede inválida: {e}")
        return

    timeout_input = input("Timeout de resposta em ms [Padrão: 500]: ").strip()
    timeout_ms = int(timeout_input) if timeout_input.isdigit() else 500

    p_ini_input = input("Porta Inicial para scan [Padrão: 1]: ").strip()
    porta_ini = int(p_ini_input) if p_ini_input.isdigit() else 1

    p_fim_input = input("Porta Final para scan [Padrão: 1024]: ").strip()
    porta_fim = int(p_fim_input) if p_fim_input.isdigit() else 1024

    hosts = [str(ip) for ip in rede.hosts()]
    print(f"\n[*] Iniciando varredura em {len(hosts)} endereços IP na rede {rede}...")
    print("-" * 75)
    print(f"{'ENDEREÇO IP':<16} | {'MAC ADDRESS':<19} | {'MÉTODO':<12} | {'STATUS'}")
    print("-" * 75)

    dispositivos_ativos = []

    # 2. Execução do Ping Sweep + ARP Probe em paralelo
    with ThreadPoolExecutor(max_workers=64) as executor:
        futures = {executor.submit(verificar_dispositivo, ip, timeout_ms): ip for ip in hosts}
        for future in as_completed(futures):
            resultado = future.result()
            if resultado:
                dispositivos_ativos.append(resultado)
                print(
                    f"{resultado['ip']:<16} | "
                    f"{resultado['mac']:<19} | "
                    f"{resultado['metodo']:<12} | "
                    f"{resultado['status']}"
                )

    # Ordena os dispositivos encontrados por endereço IP
    dispositivos_ativos.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))

    print("-" * 75)
    print(f"[*] Varredura concluída! {len(dispositivos_ativos)} dispositivo(s) ativo(s) encontrado(s).\n")

    # 3. Escaneamento de Portas Abertas nos IPs ativos
    if dispositivos_ativos:
        print(f"[*] Verificando portas abertas ({porta_ini} até {porta_fim}) nos hosts ativos...")
        print("-" * 75)
        for disp in dispositivos_ativos:
            ip = disp['ip']
            portas = escanear_faixa_portas(ip, porta_ini, porta_fim, timeout_ms)
            portas_str = ", ".join(map(str, portas)) if portas else "Nenhuma porta aberta no intervalo"
            print(f"[+] {ip:<15} (MAC: {disp['mac']}) -> Portas: {portas_str}")
        print("-" * 75)


if __name__ == "__main__":
    main()