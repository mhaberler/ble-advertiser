#!/usr/bin/env python3
"""
BLE Packet Decoder using Scapy
Parses BLE advertising packets from a pcapng file.
"""

from scapy.all import rdpcap, raw, hexdump
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
import struct

# BLE advertising types
ADV_TYPES = {
    0: "ADV_IND",
    1: "ADV_DIRECT_IND",
    2: "ADV_NONCONN_IND",
    3: "SCAN_REQ",
    4: "SCAN_RSP",
    5: "CONNECT_REQ",
    6: "ADV_SCAN_IND",
}

# GAP AD Types
AD_TYPES = {
    0x01: "Flags",
    0x02: "Incomplete 16-bit UUIDs",
    0x03: "Complete 16-bit UUIDs",
    0x04: "Incomplete 32-bit UUIDs",
    0x05: "Complete 32-bit UUIDs",
    0x06: "Incomplete 128-bit UUIDs",
    0x07: "Complete 128-bit UUIDs",
    0x08: "Short Name",
    0x09: "Complete Name",
    0x0A: "TX Power Level",
    0x0D: "Class of Device",
    0x0E: "Simple Pairing Hash",
    0x0F: "Simple Pairing Randomizer",
    0x10: "TK Value",
    0x11: "Security Manager OOB Flags",
    0x12: "Slave Connection Interval Range",
    0x14: "16-bit Service Solicitation UUIDs",
    0x15: "128-bit Service Solicitation UUIDs",
    0x16: "Service Data - 16-bit UUID",
    0x17: "Public Target Address",
    0x18: "Random Target Address",
    0x19: "Appearance",
    0x1A: "Advertising Interval",
    0x1B: "LE Bluetooth Device Address",
    0x1C: "LE Role",
    0x1D: "Simple Pairing Hash C-256",
    0x1E: "Simple Pairing Randomizer R-256",
    0x20: "Service Data - 32-bit UUID",
    0x21: "Service Data - 128-bit UUID",
    0xFF: "Manufacturer Specific Data",
}

# Company IDs
COMPANY_IDS = {
    0x0006: "Microsoft",
    0x00E0: "Google",
    0x0075: "Samsung",
    0x012D: "Xiaomi",
}

# BTHome v2 Object IDs
BTHOME_OBJECT_IDS = {
    0x00: ("packet_id", "uint8", 1, None),
    0x01: ("battery", "uint8", 1, "%"),
    0x02: ("temperature", "sint16", 2, "°C", 0.01),
    0x03: ("humidity", "uint16", 2, "%", 0.01),
    0x04: ("pressure", "uint24", 3, "hPa", 0.01),
    0x05: ("illuminance", "uint24", 3, "lux", 0.01),
    0x06: ("mass_kg", "uint16", 2, "kg", 0.01),
    0x07: ("mass_lb", "uint16", 2, "lb", 0.01),
    0x08: ("dewpoint", "sint16", 2, "°C", 0.01),
    0x09: ("count", "uint8", 1, None),
    0x0A: ("energy", "uint24", 3, "kWh", 0.001),
    0x0B: ("power", "uint24", 3, "W", 0.01),
    0x0C: ("voltage", "uint16", 2, "V", 0.001),
    0x0D: ("pm2_5", "uint16", 2, "µg/m³"),
    0x0E: ("pm10", "uint16", 2, "µg/m³"),
    0x0F: ("generic_boolean", "uint8", 1, None),
    0x10: ("power_on", "uint8", 1, None),
    0x11: ("opening", "uint8", 1, None),
    0x12: ("co2", "uint16", 2, "ppm"),
    0x13: ("tvoc", "uint16", 2, "µg/m³"),
    0x14: ("moisture", "uint16", 2, "%", 0.01),
    0x15: ("battery_low", "uint8", 1, None),
    0x16: ("battery_charging", "uint8", 1, None),
    0x17: ("carbon_monoxide", "uint8", 1, None),
    0x18: ("cold", "uint8", 1, None),
    0x19: ("connectivity", "uint8", 1, None),
    0x1A: ("door", "uint8", 1, None),
    0x1B: ("garage_door", "uint8", 1, None),
    0x1C: ("gas", "uint8", 1, None),
    0x1D: ("heat", "uint8", 1, None),
    0x1E: ("light", "uint8", 1, None),
    0x1F: ("lock", "uint8", 1, None),
    0x20: ("moisture_detected", "uint8", 1, None),
    0x21: ("motion", "uint8", 1, None),
    0x22: ("moving", "uint8", 1, None),
    0x23: ("occupancy", "uint8", 1, None),
    0x24: ("plug", "uint8", 1, None),
    0x25: ("presence", "uint8", 1, None),
    0x26: ("problem", "uint8", 1, None),
    0x27: ("running", "uint8", 1, None),
    0x28: ("safety", "uint8", 1, None),
    0x29: ("smoke", "uint8", 1, None),
    0x2A: ("sound", "uint8", 1, None),
    0x2B: ("tamper", "uint8", 1, None),
    0x2C: ("vibration", "uint8", 1, None),
    0x2D: ("window", "uint8", 1, None),
    0x2E: ("humidity_coarse", "uint8", 1, "%"),
    0x2F: ("moisture_coarse", "uint8", 1, "%"),
    0x3A: ("button", "uint8", 1, None),
    0x3C: ("dimmer", "uint16", 2, None),
    0x3D: ("count16", "uint16", 2, None),
    0x3E: ("count32", "uint32", 4, None),
    0x3F: ("rotation", "sint16", 2, "°", 0.1),
    0x40: ("distance_mm", "uint16", 2, "mm"),
    0x41: ("distance_m", "uint16", 2, "m", 0.1),
    0x42: ("duration", "uint24", 3, "s", 0.001),
    0x43: ("current", "uint16", 2, "A", 0.001),
    0x44: ("speed", "uint16", 2, "m/s", 0.01),
    0x45: ("temperature_coarse", "sint16", 2, "°C", 0.1),
    0x46: ("uv_index", "uint8", 1, None, 0.1),
    0x47: ("volume_l", "uint16", 2, "L", 0.1),
    0x48: ("volume_ml", "uint16", 2, "mL"),
    0x49: ("volume_flow_rate", "uint16", 2, "m³/hr", 0.001),
    0x4A: ("voltage_coarse", "uint16", 2, "V", 0.1),
    0x4B: ("gas_volume", "uint24", 3, "m³", 0.001),
    0x4C: ("gas_volume_alt", "uint32", 4, "m³", 0.001),
    0x4D: ("energy_alt", "uint32", 4, "kWh", 0.001),
    0x4E: ("volume_alt", "uint32", 4, "L", 0.001),
    0x4F: ("water", "uint32", 4, "L", 0.001),
    0x50: ("timestamp", "uint48", 6, "s"),
    0x51: ("acceleration", "uint16", 2, "m/s²", 0.001),
    0x52: ("gyroscope", "uint16", 2, "°/s", 0.001),
    0x62: ("speed_signed", "sint32", 4, "m/s", 0.000001),
    0x63: ("acceleration_signed", "sint32", 4, "m/s²", 0.000001),
}


def parse_bthome_v2(data: bytes) -> dict:
    """Parse BTHome v2 service data."""
    result = {"protocol": "BTHome v2", "measurements": []}
    
    if len(data) < 1:
        return result
    
    # First byte is device info
    device_info = data[0]
    encrypted = bool(device_info & 0x01)
    trigger_based = bool(device_info & 0x04)
    bthome_version = (device_info >> 5) & 0x07
    
    result["encrypted"] = encrypted
    result["trigger_based"] = trigger_based
    result["version"] = bthome_version
    
    if encrypted:
        result["note"] = "Encrypted data - cannot decode without key"
        return result
    
    # Parse measurements starting from byte 1
    offset = 1
    while offset < len(data):
        obj_id = data[offset]
        offset += 1
        
        if obj_id not in BTHOME_OBJECT_IDS:
            # Unknown object, try to skip
            result["measurements"].append({
                "type": f"unknown_0x{obj_id:02X}",
                "raw": data[offset:].hex()
            })
            break
        
        obj_info = BTHOME_OBJECT_IDS[obj_id]
        name = obj_info[0]
        data_type = obj_info[1]
        size = obj_info[2]
        unit = obj_info[3] if len(obj_info) > 3 else None
        factor = obj_info[4] if len(obj_info) > 4 else 1
        
        if offset + size > len(data):
            break
        
        raw_bytes = data[offset:offset + size]
        offset += size
        
        # Parse value based on type
        if data_type == "uint8":
            value = raw_bytes[0]
        elif data_type == "sint8":
            value = struct.unpack("b", raw_bytes)[0]
        elif data_type == "uint16":
            value = struct.unpack("<H", raw_bytes)[0]
        elif data_type == "sint16":
            value = struct.unpack("<h", raw_bytes)[0]
        elif data_type == "uint24":
            value = raw_bytes[0] | (raw_bytes[1] << 8) | (raw_bytes[2] << 16)
        elif data_type == "uint32":
            value = struct.unpack("<I", raw_bytes)[0]
        elif data_type == "sint32":
            value = struct.unpack("<i", raw_bytes)[0]
        elif data_type == "uint48":
            value = struct.unpack("<Q", raw_bytes + b'\x00\x00')[0]
        else:
            value = int.from_bytes(raw_bytes, 'little')
        
        # Apply factor
        if factor != 1:
            value = value * factor
        
        measurement = {
            "type": name,
            "value": value,
        }
        if unit:
            measurement["unit"] = unit
            measurement["display"] = f"{value}{unit}"
        
        result["measurements"].append(measurement)
    
    return result


def parse_manufacturer_data(data: bytes) -> dict:
    """Parse manufacturer-specific data."""
    if len(data) < 2:
        return {"raw": data.hex()}
    
    company_id = struct.unpack("<H", data[:2])[0]
    company_name = COMPANY_IDS.get(company_id, f"Unknown (0x{company_id:04X})")
    
    result = {
        "company_id": f"0x{company_id:04X}",
        "company_name": company_name,
        "payload": data[2:].hex(),
    }
    
    return result


def parse_ad_structures(data: bytes) -> list:
    """Parse BLE advertising data structures."""
    structures = []
    offset = 0
    
    while offset < len(data):
        if offset >= len(data):
            break
            
        length = data[offset]
        if length == 0:
            break
            
        if offset + 1 + length > len(data):
            break
            
        ad_type = data[offset + 1]
        ad_data = data[offset + 2:offset + 1 + length]
        
        ad_type_name = AD_TYPES.get(ad_type, f"Unknown (0x{ad_type:02X})")
        
        structure = {
            "type": f"0x{ad_type:02X}",
            "type_name": ad_type_name,
            "length": length - 1,
            "data": ad_data.hex(),
        }
        
        # Parse specific types
        if ad_type == 0x01:  # Flags
            flags = ad_data[0] if ad_data else 0
            flag_list = []
            if flags & 0x01: flag_list.append("LE Limited Discoverable")
            if flags & 0x02: flag_list.append("LE General Discoverable")
            if flags & 0x04: flag_list.append("BR/EDR Not Supported")
            if flags & 0x08: flag_list.append("LE+BR/EDR Controller")
            if flags & 0x10: flag_list.append("LE+BR/EDR Host")
            structure["flags"] = flag_list
            
        elif ad_type == 0x09 or ad_type == 0x08:  # Complete/Short Name
            try:
                structure["name"] = ad_data.decode('utf-8')
            except:
                structure["name"] = ad_data.hex()
                
        elif ad_type == 0x0A:  # TX Power Level
            if ad_data:
                structure["tx_power"] = struct.unpack("b", ad_data)[0]
                
        elif ad_type == 0xFF:  # Manufacturer Data
            structure["manufacturer"] = parse_manufacturer_data(ad_data)
            
        elif ad_type == 0x16:  # Service Data - 16-bit UUID
            if len(ad_data) >= 2:
                uuid = struct.unpack("<H", ad_data[:2])[0]
                structure["uuid"] = f"0x{uuid:04X}"
                structure["service_data"] = ad_data[2:].hex()
                
                # BTHome v2 UUID
                if uuid == 0xFCD2:
                    structure["bthome"] = parse_bthome_v2(ad_data[2:])
        
        structures.append(structure)
        offset += 1 + length
    
    return structures


def parse_nordic_ble_packet(raw_data: bytes) -> dict:
    """Parse Nordic BLE sniffer packet format or raw BLE packet."""
    result = {}
    
    # Nordic BLE Sniffer header format:
    # - Board ID (1 byte)
    # - Packet counter (2 bytes, little endian)
    # - Packet type (1 byte)
    # - Flags (1 byte)
    # - Channel (1 byte)
    # - RSSI (1 byte, signed)
    # - Event counter (2 bytes)
    # - Timestamp (4 bytes)
    # - BLE packet follows...
    
    if len(raw_data) < 20:
        return result
    
    # Try to find BLE advertising access address (0x8E89BED6)
    # In Little Endian this is: D6 BE 89 8E
    ble_aa = bytes([0xD6, 0xBE, 0x89, 0x8E])
    aa_pos = raw_data.find(ble_aa)
    
    if aa_pos == -1:
        # Try alternative - look for standard advertising patterns
        return result
    
    result["access_addr"] = "0x8E89BED6"
    result["type"] = "Advertising"
    
    # BLE packet starts at access address
    ble_pkt = raw_data[aa_pos:]
    
    if len(ble_pkt) < 6:
        return result
    
    # Skip access address (4 bytes), then PDU header
    pdu_offset = 4
    
    if len(ble_pkt) <= pdu_offset:
        return result
    
    # PDU header: type (4 bits), RFU (2 bits), TxAdd (1 bit), RxAdd (1 bit)
    pdu_header = ble_pkt[pdu_offset]
    pdu_type = pdu_header & 0x0F
    tx_add = (pdu_header >> 6) & 0x01  # 0 = public, 1 = random
    
    result["pdu_type"] = pdu_type
    result["adv_type"] = ADV_TYPES.get(pdu_type, f"Unknown ({pdu_type})")
    result["tx_addr_type"] = "Random" if tx_add else "Public"
    
    # PDU length
    pdu_length = ble_pkt[pdu_offset + 1]
    result["pdu_length"] = pdu_length
    
    # Advertiser address (6 bytes) - for most ADV types
    if pdu_type in [0, 1, 2, 4, 6] and len(ble_pkt) > pdu_offset + 8:
        addr_bytes = ble_pkt[pdu_offset + 2:pdu_offset + 8]
        addr_str = ":".join(f"{b:02X}" for b in reversed(addr_bytes))
        result["adv_addr"] = addr_str
        
        # Advertising data follows address
        ad_data_start = pdu_offset + 8
        ad_data_len = pdu_length - 6  # PDU length minus address
        
        if ad_data_len > 0 and len(ble_pkt) >= ad_data_start + ad_data_len:
            ad_data = ble_pkt[ad_data_start:ad_data_start + ad_data_len]
            result["ad_structures"] = parse_ad_structures(ad_data)
    
    return result


def decode_ble_packet(pkt, pkt_num: int):
    """Decode a single BLE packet."""
    result = {"packet_num": pkt_num}
    
    # Try to extract raw bytes
    try:
        raw_data = raw(pkt)
    except:
        raw_data = bytes(pkt)
    
    result["raw_hex"] = raw_data.hex()
    result["length"] = len(raw_data)
    
    # Check for BTLE layer
    if BTLE in pkt:
        btle = pkt[BTLE]
        result["access_addr"] = f"0x{btle.access_addr:08X}"
        
        # Check for advertising packets
        if BTLE_ADV in pkt:
            adv = pkt[BTLE_ADV]
            result["type"] = "Advertising"
            pdu_type = adv.PDU_type if hasattr(adv, 'PDU_type') else None
            if pdu_type is not None:
                result["adv_type"] = ADV_TYPES.get(pdu_type, f"Unknown ({pdu_type})")
            
            # Get advertiser address
            if hasattr(adv, 'AdvA'):
                result["adv_addr"] = adv.AdvA
                
        # Check for advertising data
        if BTLE_ADV_IND in pkt:
            adv_ind = pkt[BTLE_ADV_IND]
            if hasattr(adv_ind, 'data'):
                ad_data = bytes(adv_ind.data) if adv_ind.data else b''
                if ad_data:
                    result["ad_structures"] = parse_ad_structures(ad_data)
                    
        if BTLE_ADV_NONCONN_IND in pkt:
            adv_nc = pkt[BTLE_ADV_NONCONN_IND]
            if hasattr(adv_nc, 'data'):
                ad_data = bytes(adv_nc.data) if adv_nc.data else b''
                if ad_data:
                    result["ad_structures"] = parse_ad_structures(ad_data)
                    
        if BTLE_SCAN_RSP in pkt:
            scan_rsp = pkt[BTLE_SCAN_RSP]
            if hasattr(scan_rsp, 'data'):
                ad_data = bytes(scan_rsp.data) if scan_rsp.data else b''
                if ad_data:
                    result["scan_rsp_structures"] = parse_ad_structures(ad_data)
                    
        # Check for data packets
        if BTLE_DATA in pkt:
            result["type"] = "Data"
            data_pkt = pkt[BTLE_DATA]
            if hasattr(data_pkt, 'LLID'):
                result["llid"] = data_pkt.LLID
    else:
        # Try parsing as Nordic BLE sniffer format or raw BLE
        nordic_result = parse_nordic_ble_packet(raw_data)
        result.update(nordic_result)
                
    # Nordic BLE Sniffer format
    if hasattr(pkt, 'load'):
        result["payload"] = pkt.load.hex() if isinstance(pkt.load, bytes) else str(pkt.load)
    
    return result


def print_packet_info(info: dict):
    """Pretty print packet information."""
    print(f"\n{'='*60}")
    print(f"Packet #{info.get('packet_num', '?')}")
    print(f"{'='*60}")
    print(f"  Length: {info.get('length', 0)} bytes")
    
    if 'access_addr' in info:
        print(f"  Access Address: {info['access_addr']}")
        
    if 'type' in info:
        print(f"  Type: {info['type']}")
        
    if 'tx_addr_type' in info:
        print(f"  Address Type: {info['tx_addr_type']}")
        
    if 'adv_type' in info:
        print(f"  ADV Type: {info['adv_type']}")
        
    if 'adv_addr' in info:
        print(f"  Advertiser Address: {info['adv_addr']}")
        
    if 'ad_structures' in info:
        print(f"\n  Advertising Data Structures:")
        for ad in info['ad_structures']:
            print(f"    - {ad['type_name']} ({ad['type']})")
            print(f"      Data: {ad['data']}")
            if 'flags' in ad:
                print(f"      Flags: {', '.join(ad['flags'])}")
            if 'name' in ad:
                print(f"      Name: {ad['name']}")
            if 'tx_power' in ad:
                print(f"      TX Power: {ad['tx_power']} dBm")
            if 'manufacturer' in ad:
                mfg = ad['manufacturer']
                print(f"      Company: {mfg.get('company_name', 'Unknown')}")
            if 'uuid' in ad:
                print(f"      UUID: {ad['uuid']}")
            if 'bthome' in ad:
                bth = ad['bthome']
                print(f"      Protocol: {bth.get('protocol', 'BTHome')}")
                print(f"      Encrypted: {bth.get('encrypted', False)}")
                if bth.get('measurements'):
                    print(f"      Measurements:")
                    for m in bth['measurements']:
                        if 'display' in m:
                            print(f"        - {m['type']}: {m['display']}")
                        elif 'value' in m:
                            print(f"        - {m['type']}: {m['value']}")
                        elif 'raw' in m:
                            print(f"        - {m['type']}: (raw: {m['raw']})")
                    
    if 'scan_rsp_structures' in info:
        print(f"\n  Scan Response Data:")
        for ad in info['scan_rsp_structures']:
            print(f"    - {ad['type_name']} ({ad['type']})")
            print(f"      Data: {ad['data']}")
            
    print(f"\n  Raw: {info.get('raw_hex', '')[:80]}...")


def main():
    import sys
    
    # Default pcapng file
    pcap_file = "ble.pcapng"
    
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    
    print(f"Loading {pcap_file}...")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"Error loading pcap file: {e}")
        return
    
    print(f"Loaded {len(packets)} packets")
    print(f"\n{'#'*60}")
    print(f"BLE Packet Decoder")
    print(f"{'#'*60}")
    
    # Statistics
    stats = {
        "total": len(packets),
        "ble_adv": 0,
        "ble_data": 0,
        "addresses": set(),
    }
    
    for i, pkt in enumerate(packets):
        info = decode_ble_packet(pkt, i + 1)
        print_packet_info(info)
        
        # Update stats
        if info.get('type') == 'Advertising':
            stats['ble_adv'] += 1
        elif info.get('type') == 'Data':
            stats['ble_data'] += 1
            
        if 'adv_addr' in info:
            stats['addresses'].add(info['adv_addr'])
    
    # Print summary
    print(f"\n\n{'#'*60}")
    print("SUMMARY")
    print(f"{'#'*60}")
    print(f"Total packets: {stats['total']}")
    print(f"Advertising packets: {stats['ble_adv']}")
    print(f"Data packets: {stats['ble_data']}")
    print(f"Unique addresses: {len(stats['addresses'])}")
    
    if stats['addresses']:
        print(f"\nAddresses seen:")
        for addr in sorted(stats['addresses']):
            print(f"  - {addr}")


if __name__ == "__main__":
    main()
