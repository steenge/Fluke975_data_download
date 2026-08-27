#!/usr/bin/env python3

import argparse
import csv
import math
import serial
import struct
import sys
import time
from datetime import datetime


# ----------------------------------------------------------------------
# CRC
# ----------------------------------------------------------------------

def crc16_modbus(data: bytes) -> int:
    """
    CRC-16/MODBUS
    Polynomial: 0xA001
    Initial value: 0xFFFF
    """
    crc = 0xFFFF

    for byte in data:
        crc ^= byte

        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1

    return crc


def add_crc(data: bytes) -> bytes:
    """
    Append CRC low-byte first.
    """
    crc = crc16_modbus(data)
    return data + struct.pack("<H", crc)


def verify_crc(data: bytes) -> bool:
    """
    Verify a packet where the final two bytes are CRC16/MODBUS.
    """
    if len(data) < 3:
        return False

    payload = data[:-2]
    received_crc = struct.unpack("<H", data[-2:])[0]
    calculated_crc = crc16_modbus(payload)

    return received_crc == calculated_crc


# ----------------------------------------------------------------------
# Utility functions
# ----------------------------------------------------------------------

def bcd(value: int) -> int:
    """
    Convert one BCD byte to integer.
    Example:
      0x49 -> 49
    """
    return ((value >> 4) * 10) + (value & 0x0F)


def decode_timestamp(raw: bytes) -> datetime:
    """
    Decode Fluke timestamp:
      HH MM SS DD MM YY
    """
    if len(raw) != 6:
        raise ValueError("Timestamp must be exactly 6 bytes")

    return datetime(
        2000 + bcd(raw[5]),
        bcd(raw[4]),
        bcd(raw[3]),
        bcd(raw[0]),
        bcd(raw[1]),
        bcd(raw[2])
    )


def read_response(
    ser,
    expected_length=None,
    timeout=2.0
):
    """
    Read bytes until expected length is reached
    or timeout expires.
    """
    start = time.time()
    data = bytearray()

    while time.time() - start < timeout:

        waiting = ser.in_waiting

        if waiting:
            data.extend(ser.read(waiting))

            if (
                expected_length is not None
                and len(data) >= expected_length
            ):
                break

        else:
            time.sleep(0.01)

    return bytes(data)


def send_simple_command(
    ser,
    command: bytes,
    expected_length=None,
    timeout=2.0
):
    ser.reset_input_buffer()
    ser.write(command)
    ser.flush()

    return read_response(
        ser,
        expected_length=expected_length,
        timeout=timeout
    )


# ----------------------------------------------------------------------
# Fluke commands
# ----------------------------------------------------------------------

def get_id(ser):
    """
    Query instrument identification.
    """
    response = send_simple_command(
        ser,
        b"ID\r",
        expected_length=31,
        timeout=2.0
    )

    if len(response) < 4:
        raise RuntimeError(
            "No valid response to ID command"
        )

    if not response.startswith(b"0\r"):
        raise RuntimeError(
            f"Instrument returned error to ID: {response!r}"
        )

    return response


def make_qd0():
    """
    Query the session directory / log metadata.
    """
    return add_crc(b"QD 0\r")


def make_qd2(block_number: int):
    """
    Build command to download one 256-byte data block.

    Observed selector layout:
      00
      block_number uint16 little-endian
      00
    """
    if not 0 <= block_number <= 0xFFFF:
        raise ValueError(
            "QD 2 block number must be between 0 and 65535"
        )

    selector = (
        b"\x00"
        + struct.pack("<H", block_number)
        + b"\x00"
    )

    cmd = b"QD 2" + selector + b"\r"

    return add_crc(cmd)


# ----------------------------------------------------------------------
# Session directory (QD 0)
# ----------------------------------------------------------------------

def get_sessions(ser):
    """
    Read and parse the complete QD 0 session directory.

    Observed QD 0 response:
      0\r                    2 bytes
      QD 0                   4 bytes
      session_count          1 byte
      session entries        16 bytes each
      CRC                    2 bytes

    Each 16-byte session entry:
      timestamp              6 bytes, BCD HH MM SS DD MM YY
      start_address          4 bytes, little-endian
      record_count           4 bytes, little-endian
      unknown                2 bytes

    Example observed with three sessions:
      count = 03

      session 1:
        timestamp = 2026-08-23 17:35:07
        address   = 0x00000000
        records   = 31

      session 2:
        timestamp = 2026-08-23 17:40:49
        address   = 0x00000400
        records   = 31

      session 3:
        timestamp = 2026-08-23 17:47:16
        address   = 0x00000800
        records   = 31
    """

    cmd = make_qd0()

    ser.reset_input_buffer()
    ser.write(cmd)
    ser.flush()

    response = read_response(
        ser,
        timeout=2.0
    )

    if not response.startswith(b"0\rQD 0"):
        raise RuntimeError(
            "Unexpected QD 0 response:\n"
            + response.hex(" ")
        )

    if not verify_crc(response):
        raise RuntimeError(
            "QD 0 CRC check failed"
        )

    payload = response[6:-2]

    if len(payload) < 1:
        raise RuntimeError(
            "QD 0 payload is empty"
        )

    session_count = payload[0]

    expected_payload_length = 1 + session_count * 16

    if len(payload) != expected_payload_length:
        raise RuntimeError(
            "Unexpected QD 0 payload length: "
            f"session_count={session_count}, "
            f"expected {expected_payload_length} bytes, "
            f"received {len(payload)} bytes.\n"
            f"Raw response: {response.hex(' ')}"
        )

    sessions = []

    for i in range(session_count):

        offset = 1 + i * 16
        entry = payload[offset:offset + 16]

        timestamp_raw = entry[0:6]

        try:
            timestamp = decode_timestamp(timestamp_raw)
        except ValueError as e:
            raise RuntimeError(
                f"Invalid timestamp in session {i + 1}"
            ) from e

        start_address = struct.unpack_from(
            "<I",
            entry,
            6
        )[0]

        record_count = struct.unpack_from(
            "<I",
            entry,
            10
        )[0]

        unknown = entry[14:16]

        if start_address % 256 != 0:
            raise RuntimeError(
                f"Session {i + 1}: start address "
                f"0x{start_address:08x} is not aligned "
                "to a 256-byte QD 2 block"
            )

        sessions.append({
            "session": i + 1,
            "timestamp": timestamp,
            "start_address": start_address,
            "start_block": start_address // 256,
            "record_count": record_count,
            "unknown_hex": unknown.hex()
        })

    return sessions


# ----------------------------------------------------------------------
# Block download
# ----------------------------------------------------------------------

def download_block(
    ser,
    block_number
):
    """
    Download one 256-byte block.

    Expected response:
      0\r                  2 bytes
      QD 2                 4 bytes
      block selector       4 bytes
      data                 256 bytes
      CRC                  2 bytes

    Total: 268 bytes
    """

    cmd = make_qd2(block_number)

    ser.reset_input_buffer()
    ser.write(cmd)
    ser.flush()

    response = read_response(
        ser,
        expected_length=268,
        timeout=3.0
    )

    if len(response) != 268:
        raise RuntimeError(
            f"Block {block_number}: "
            f"expected 268 bytes, "
            f"received {len(response)}; "
            f"response={response.hex(' ')}"
        )

    if not response.startswith(b"0\rQD 2"):
        raise RuntimeError(
            f"Block {block_number}: "
            "unexpected response header"
        )

    if not verify_crc(response):
        raise RuntimeError(
            f"Block {block_number}: CRC error"
        )

    expected_selector = (
        b"\x00"
        + struct.pack("<H", block_number)
        + b"\x00"
    )

    returned_selector = response[6:10]

    if returned_selector != expected_selector:
        raise RuntimeError(
            f"Block selector mismatch: "
            f"requested {expected_selector.hex(' ')}, "
            f"received {returned_selector.hex(' ')}"
        )

    return response[10:266]


# ----------------------------------------------------------------------
# Record parsing
# ----------------------------------------------------------------------

def parse_record(data: bytes):
    """
    Parse one 32-byte logged measurement record.
    """
    if len(data) != 32:
        raise ValueError(
            "Record must be exactly 32 bytes"
        )

    record_type = struct.unpack_from(
        "<H",
        data,
        0
    )[0]

    record_number = struct.unpack_from(
        "<H",
        data,
        2
    )[0]

    # Empty/unused record
    if record_number == 0:
        return None

    try:
        timestamp = decode_timestamp(
            data[4:10]
        )
    except ValueError:
        timestamp = None

    temperature = struct.unpack_from(
        "<h",
        data,
        10
    )[0] / 10.0

    rh = struct.unpack_from(
        "<H",
        data,
        12
    )[0] / 100.0

    dewpoint = struct.unpack_from(
        "<h",
        data,
        14
    )[0] / 10.0

    wetbulb = struct.unpack_from(
        "<h",
        data,
        16
    )[0] / 10.0

    co = struct.unpack_from(
        "<H",
        data,
        18
    )[0]

    co2 = struct.unpack_from(
        "<I",
        data,
        20
    )[0]

    unknown = data[24:32]

    return {
        "record_type": record_type,
        "record": record_number,
        "timestamp": timestamp,
        "temperature_c": temperature,
        "rh_percent": rh,
        "dewpoint_c": dewpoint,
        "wetbulb_c": wetbulb,
        "co_ppm": co,
        "co2_ppm": co2,
        "unknown_hex": unknown.hex()
    }


# ----------------------------------------------------------------------
# Session download
# ----------------------------------------------------------------------

def download_session(ser, session):
    """
    Download one complete session.

    The session's own start address and record count are used, so sessions
    may have different lengths and do not need to be contiguous.
    """
    record_count = session["record_count"]
    start_block = session["start_block"]

    if record_count == 0:
        return []

    blocks = math.ceil(record_count / 8)

    records = []

    print(
        f"Downloading session {session['session']}: "
        f"{record_count} records from {blocks} block(s), "
        f"starting at block {start_block}..."
    )

    for relative_block in range(blocks):

        block_number = start_block + relative_block

        print(
            f"  Block {relative_block + 1}/{blocks} "
            f"(absolute block {block_number})",
            end="\r",
            flush=True
        )

        block = download_block(
            ser,
            block_number
        )

        for index in range(8):

            raw_record = block[
                index * 32:
                (index + 1) * 32
            ]

            record = parse_record(
                raw_record
            )

            if record is None:
                continue

            row = record.copy()
            row["session"] = session["session"]
            row["session_start"] = session["timestamp"]
            row["session_start_address"] = session["start_address"]
            row["session_record_count"] = session["record_count"]

            records.append(row)

            if len(records) >= record_count:
                break

        if len(records) >= record_count:
            break

    print()

    if len(records) != record_count:
        print(
            f"WARNING: Session {session['session']} reported "
            f"{record_count} records, but {len(records)} "
            "records were decoded.",
            file=sys.stderr
        )

    return records


# ----------------------------------------------------------------------
# CSV
# ----------------------------------------------------------------------

def write_csv(filename, records):

    fields = [
        "session",
        "session_start",
        "session_start_address",
        "session_record_count",
        "record",
        "timestamp",
        "temperature_c",
        "rh_percent",
        "dewpoint_c",
        "wetbulb_c",
        "co_ppm",
        "co2_ppm",
        "record_type",
        "unknown_hex"
    ]

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        writer.writeheader()

        for record in records:

            row = record.copy()

            if row["session_start"]:
                row["session_start"] = (
                    row["session_start"]
                    .strftime("%Y-%m-%d %H:%M:%S")
                )

            if row["timestamp"]:
                row["timestamp"] = (
                    row["timestamp"]
                    .strftime("%Y-%m-%d %H:%M:%S")
                )

            writer.writerow({
                field: row[field]
                for field in fields
            })


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Download all logged sessions "
            "from a Fluke 975 AirMeter"
        )
    )

    parser.add_argument(
        "--port",
        default="/dev/ttyACM0",
        help=(
            "Serial port "
            "(default: /dev/ttyACM0)"
        )
    )

    parser.add_argument(
        "--output",
        default="fluke975.csv",
        help=(
            "CSV output filename "
            "(default: fluke975.csv)"
        )
    )

    args = parser.parse_args()

    print(
        f"Opening {args.port}"
    )

    with serial.Serial(
        port=args.port,
        baudrate=9600,
        bytesize=serial.EIGHTBITS,
        parity=serial.PARITY_NONE,
        stopbits=serial.STOPBITS_ONE,
        timeout=0.1
    ) as ser:

        # Identification
        id_response = get_id(ser)

        id_payload = id_response[2:-2]

        id_text = (
            id_payload
            .decode(
                "ascii",
                errors="replace"
            )
            .replace("\r", "")
            .strip()
        )

        print(
            f"Instrument: {id_text}"
        )

        # Session directory
        sessions = get_sessions(ser)

        print()
        print(
            f"Sessions found: {len(sessions)}"
        )

        if not sessions:
            print(
                "No logged sessions found in instrument."
            )
            return

        print()

        for session in sessions:

            print(
                f"Session {session['session']:3d}: "
                f"{session['timestamp']:%Y-%m-%d %H:%M:%S}  "
                f"records={session['record_count']:5d}  "
                f"address=0x{session['start_address']:08x}  "
                f"block={session['start_block']}"
            )

        print()

        # Download every session
        all_records = []

        for session in sessions:

            records = download_session(
                ser,
                session
            )

            all_records.extend(
                records
            )

    print()
    print(
        f"Downloaded {len(all_records)} records "
        f"from {len(sessions)} session(s)"
    )

    # Show first few records from each session
    print()

    for session in sessions:

        session_records = [
            r for r in all_records
            if r["session"] == session["session"]
        ]

        print(
            f"Session {session['session']}:"
        )

        for record in session_records[:3]:

            timestamp = (
                record["timestamp"]
                .strftime("%Y-%m-%d %H:%M:%S")
                if record["timestamp"]
                else "INVALID"
            )

            print(
                f'  {record["record"]:5d}  '
                f'{timestamp}  '
                f'{record["temperature_c"]:5.1f} °C  '
                f'{record["rh_percent"]:6.2f} %RH  '
                f'CO={record["co_ppm"]} ppm  '
                f'CO2={record["co2_ppm"]} ppm'
            )

        if len(session_records) > 3:
            print("  ...")

    # Save combined CSV
    write_csv(
        args.output,
        all_records
    )

    print()
    print(
        f"Saved to {args.output}"
    )


if __name__ == "__main__":
    main()
