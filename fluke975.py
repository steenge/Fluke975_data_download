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

    received_crc = struct.unpack(
        "<H",
        data[-2:]
    )[0]

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
            data.extend(
                ser.read(waiting)
            )

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
    Query log metadata.
    """
    return add_crc(
        b"QD 0\r"
    )


def make_qd2(block_number: int):
    """
    Build command to download one 256-byte data block.

    QD 2
    + selector byte 00
    + 2-byte little-endian block number
    + reserved byte 00
    + CR
    + CRC
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
# Log metadata
# ----------------------------------------------------------------------

def get_log_info(ser):
    """
    Query QD 0 metadata.

    Observed reply:

      0\r
      QD 0
      01
      HH MM SS DD MM YY
      00 00 00 00
      record_count (4-byte little-endian)
      00 00
      CRC
    """

    cmd = make_qd0()

    ser.reset_input_buffer()

    ser.write(cmd)
    ser.flush()

    response = read_response(
        ser,
        timeout=2.0
    )

    if not response.startswith(
        b"0\rQD 0"
    ):
        raise RuntimeError(
            "Unexpected QD 0 response:\n"
            + response.hex(" ")
        )

    #
    # IMPORTANT:
    # Response CRC covers the COMPLETE response,
    # including initial status bytes 0\r.
    #
    if not verify_crc(response):
        raise RuntimeError(
            "QD 0 CRC check failed"
        )

    #
    # Skip:
    # 0\r      = 2 bytes
    # QD 0     = 4 bytes
    #
    payload = response[6:-2]

    if len(payload) < 17:
        raise RuntimeError(
            f"QD 0 payload too short: "
            f"{len(payload)} bytes"
        )

    log_type = payload[0]

    timestamp_raw = payload[1:7]

    try:
        timestamp = datetime(
            2000 + bcd(timestamp_raw[5]),
            bcd(timestamp_raw[4]),
            bcd(timestamp_raw[3]),
            bcd(timestamp_raw[0]),
            bcd(timestamp_raw[1]),
            bcd(timestamp_raw[2])
        )

    except ValueError as e:
        raise RuntimeError(
            "Invalid timestamp in QD 0 response"
        ) from e

    #
    # Four zero bytes follow timestamp.
    #
    # record_count therefore starts at offset 11.
    #
    record_count = struct.unpack_from(
        "<I",
        payload,
        11
    )[0]

    return {
        "log_type": log_type,
        "timestamp": timestamp,
        "record_count": record_count,
        "raw": response
    }


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

    cmd = make_qd2(
        block_number
    )

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

    if not response.startswith(
        b"0\rQD 2"
    ):
        raise RuntimeError(
            f"Block {block_number}: "
            f"unexpected response header"
        )

    #
    # CRC is calculated across entire response,
    # excluding only final CRC bytes.
    #
    if not verify_crc(response):
        raise RuntimeError(
            f"Block {block_number}: CRC error"
        )

    #
    # The instrument echoes the four selector bytes. Verify them too.
    #
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

    #
    # 256-byte payload:
    #
    data = response[10:266]

    return data


# ----------------------------------------------------------------------
# Record parsing
# ----------------------------------------------------------------------

def parse_record(
    data: bytes
):
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

    #
    # Empty/unused record
    #
    if record_number == 0:
        return None

    hour = bcd(data[4])
    minute = bcd(data[5])
    second = bcd(data[6])

    day = bcd(data[7])
    month = bcd(data[8])
    year = 2000 + bcd(data[9])

    try:
        timestamp = datetime(
            year,
            month,
            day,
            hour,
            minute,
            second
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
# Complete download
# ----------------------------------------------------------------------

def download_records(
    ser,
    record_count
):
    """
    Download all records.

    One block:
      256 bytes

    One record:
      32 bytes

    Therefore:
      8 records per block.
    """

    blocks = math.ceil(
        record_count / 8
    )

    records = []

    print(
        f"Downloading {record_count} records "
        f"from {blocks} blocks..."
    )

    for block_number in range(
        blocks
    ):

        print(
            f"Block "
            f"{block_number + 1}/{blocks}",
            end="\r",
            flush=True
        )

        block = download_block(
            ser,
            block_number
        )

        for index in range(8):

            start = index * 32
            end = start + 32

            raw_record = block[
                start:end
            ]

            record = parse_record(
                raw_record
            )

            if record is None:
                continue

            records.append(
                record
            )

            if (
                len(records)
                >= record_count
            ):
                break

        if (
            len(records)
            >= record_count
        ):
            break

    print()

    return records


# ----------------------------------------------------------------------
# CSV
# ----------------------------------------------------------------------

def write_csv(
    filename,
    records
):

    fields = [
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

            if row["timestamp"]:
                row["timestamp"] = (
                    row["timestamp"]
                    .strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
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
            "Download logged data "
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

        #
        # Identification
        #
        id_response = get_id(
            ser
        )

        #
        # ID format observed:
        #
        # 0\r
        # FLUKE 975, 1C , 93870022  \r
        # CRC
        #
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

        #
        # Metadata
        #
        info = get_log_info(
            ser
        )

        print(
            "Log start:",
            info["timestamp"]
            .strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        )

        print(
            "Records:",
            info["record_count"]
        )

        if info["record_count"] == 0:

            print(
                "No logged records "
                "found in instrument."
            )

            return

        #
        # Download all records
        #
        records = download_records(
            ser,
            info["record_count"]
        )

    print(
        f"Downloaded "
        f"{len(records)} records"
    )

    #
    # Sanity check
    #
    if (
        len(records)
        != info["record_count"]
    ):

        print(
            "WARNING: Instrument reported "
            f"{info['record_count']} records, "
            f"but {len(records)} were decoded.",
            file=sys.stderr
        )

    #
    # Show first few
    #
    print()

    for record in records[:5]:

        timestamp = (
            record["timestamp"]
            .strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if record["timestamp"]
            else "INVALID"
        )

        print(
            f'{record["record"]:5d}  '
            f'{timestamp}  '
            f'{record["temperature_c"]:5.1f} °C  '
            f'{record["rh_percent"]:6.2f} %RH  '
            f'CO={record["co_ppm"]} ppm  '
            f'CO2={record["co2_ppm"]} ppm'
        )

    if len(records) > 5:
        print("...")

    #
    # Save CSV
    #
    write_csv(
        args.output,
        records
    )

    print()

    print(
        f"Saved to {args.output}"
    )


if __name__ == "__main__":
    main()
