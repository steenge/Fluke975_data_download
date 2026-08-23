Tool to download logged entries from the Fluke 975 airmeter. The data is saved as csv.

Run as python3 fluke975.py --port /dev/ttyACM0 --output fluke975.csv



Fluke 975
   │ USB
   ▼
Linux cdc_acm
   │
   ▼
/dev/ttyACM0
   │
   ▼
Python / pyserial
   │
   ├── ID
   ├── QD 0  → log-information + antal records
   ├── QD 2  → download af blokke
   ├── CRC-16/MODBUS
   ▼
32-byte records
   │
   ▼
CSV
