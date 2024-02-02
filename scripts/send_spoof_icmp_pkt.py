#!/usr/bin/python3

from scapy.all import IP, ICMP, send
import click

"""
This script is used to send a spoofed ICMP packet to a target IP address.
"""

@click.command()
@click.option("--target-ip", prompt="Target IP", help="IP address of the target")
@click.option("--source-ip", prompt="Source IP", help="IP address of the source")
def send_spoof_icmp_packet(target_ip: str, source_ip: str):
    icmp_packet = IP(src=source_ip, dst=target_ip) / ICMP()
    send(icmp_packet, verbose=0)
    print("ICMP packet sent from {0} to {1}".format(source_ip, target_ip))

if __name__ == "__main__":
    send_spoof_icmp_packet()
