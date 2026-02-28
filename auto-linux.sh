#!/bin/bash

# WireGuard Interface Management Script
# Author: umut0301
# Version: v57.0

# Function to modify MTU
modify_mtu() {
    echo "Enter the interface name (e.g., wg0):"
    read interface
    echo "Enter the new MTU value:"
    read mtu
    ip link set dev "$interface" mtu "$mtu"
    echo "MTU for $interface set to $mtu."
}

# Function to modify subnet
modify_subnet() {
    echo "Enter the interface name (e.g., wg0):"
    read interface
    echo "Enter the new subnet (e.g., 10.0.0.1/24):"
    read subnet
    ip addr add "$subnet" dev "$interface"
    echo "Subnet for $interface set to $subnet."
}

# Function to restart interface
restart_interface() {
    echo "Enter the interface name (e.g., wg0):"
    read interface
    wg-quick down "$interface"
    wg-quick up "$interface"
    echo "Interface $interface restarted."
}

# Main menu
while true; do
    echo "
WireGuard Interface Management Menu"
    echo "1. Modify MTU"
    echo "2. Modify Subnet"
    echo "3. Restart Interface"
    echo "4. Exit"
    read choice

    case $choice in
        1) modify_mtu ;;  
        2) modify_subnet ;;  
        3) restart_interface ;;  
        4) break ;;  
        *) echo "Invalid option. Please try again." ;;  
    esac
done
