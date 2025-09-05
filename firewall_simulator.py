
from flask import Flask, render_template, request
from ipaddress import ip_network, ip_address

firewall_simulator = Flask(__name__)

#firewall rules
rules = [
    {"src_ip": "192.168.1.0/24", "dst_ip": "any", "port": 80, "protocol": "TCP", "action": "ALLOW"},
    {"src_ip": "any", "dst_ip": "any", "port": 22, "protocol": "TCP", "action": "DENY"},
    {"src_ip": "any", "dst_ip": "any", "port": "any", "protocol": "any", "action": "ALLOW"},
]

def ip_match(packet_ip, rule_ip):
    if rule_ip == "any":
        return True
    try:
        return ip_address(packet_ip) in ip_network(rule_ip)
    except ValueError:
        return False

def port_match(packet_port, rule_port):
    return rule_port == "any" or int(packet_port) == int(rule_port)

def protocol_match(packet_proto, rule_proto):
    return rule_proto == "any" or packet_proto.upper() == rule_proto.upper()

def simulate_packet(packet):
    for idx, rule in enumerate(rules):
        if (ip_match(packet['src_ip'], rule['src_ip']) and
            ip_match(packet['dst_ip'], rule['dst_ip']) and
            port_match(packet['port'], rule['port']) and
            protocol_match(packet['protocol'], rule['protocol'])):
            return f"Packet matched Rule #{idx+1}: Action = {rule['action']}"
    return "No matching rule. Default action: DENY"

@firewall_simulator.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        packet = {
            'src_ip': request.form['src_ip'],
            'dst_ip': request.form['dst_ip'],
            'port': request.form['port'],
            'protocol': request.form['protocol']
        }
        result = simulate_packet(packet)
    return render_template('index.html', result=result)

if __name__ == '__main__':
    firewall_simulator.run(debug=True)
