# python -m pip install numpy scipy pandas pyshark soundfile
# In Wireshark: File → Export Packet Dissections 
# frame.time_epoch, wlan.fc.type_subtype, wlan_mgt.ssid, wlan_radio.frequency, wlan_radio.channel_width
# python timeline_mapper.py --ws-csv export.csv --audio mic.wav --out timeline.csv --mine-top 10
# 
# option B: pyshark needs tshark (Wireshark) in PATH. If you don’t have it,
# export a CSV from Wireshark and use --ws-csv instead of --pcap.
# python timeline_mapper.py --pcap capture.pcapng --audio mic.wav --out timeline.csv \
# --motif "wifi5_20,ultra19,wifi6_20" --gap 2.0
#!/usr/bin/env python3
"""
timeline_mapper.py

Build a unified timeline from Wireshark logs + an audio recording,
then detect repeating RF→ultrasound→RF sequences.

Inputs:
  - PCAP/PCAPNG (requires tshark/pyshark) OR a Wireshark-exported CSV
  - WAV audio (mono or stereo)

Outputs:
  - CSV timeline (events fused & sorted)
  - Console summary of detected sequences (counts, timings)

Usage examples:
  python timeline_mapper.py --pcap capture.pcapng --audio mic.wav --out timeline.csv \
      --motif "wifi5_20,ultra19,wifi6_20" --gap 2.0

  # If you can’t use tshark/pyshark, export a CSV from Wireshark with
  # fields: frame.time_epoch, wlan.fc.type_subtype, wlan_mgt.ssid,
  # wlan_radio.frequency, wlan_radio.channel_width
  python timeline_mapper.py --ws-csv ws.csv --audio mic.wav --out timeline.csv --mine-top 10
"""

import argparse
import csv
import math
import os
import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict

import numpy as np
import pandas as pd

# Audio libs
import soundfile as sf
from scipy.signal import stft

# Optional (pcap path); we only import if used
try:
    import pyshark  # type: ignore
except Exception:
    pyshark = None


@dataclass
class Event:
    ts: float                 # epoch seconds (float)
    source: str               # 'wifi' or 'audio'
    label: str                # e.g., 'wifi_beacon_5g_20', 'ultra_18_21khz'
    meta: Dict[str, str]      # anything extra (ssid, freq, width, etc.)


def _band_from_freq(freq_hz: Optional[float]) -> Optional[str]:
    if freq_hz is None:
        return None
    if 2400e6 <= freq_hz <= 2500e6:
        return '2g4'
    if 5150e6 <= freq_hz <= 5945e6:
        return '5g'
    if 5925e6 <= freq_hz <= 7125e6:
        return '6g'
    return None


def _width_from_ws(width_field: Optional[str]) -> Optional[str]:
    """
    Map Wireshark wlan_radio.channel_width to MHz text.
    Common enum values:
      0=20, 1=40, 2=80, 3=160, 4=80+80, 5=5, 6=10
    We only normalize to '5','10','20','40','80','160'.
    """
    if width_field is None or width_field == '':
        return None
    try:
        i = int(width_field)
        mapping = {0: '20', 1: '40', 2: '80', 3: '160', 4: '80', 5: '5', 6: '10'}
        return mapping.get(i)
    except Exception:
        # Some exports already show MHz numerically
        m = re.search(r'(\d+)', str(width_field))
        return m.group(1) if m else None


def _run_tshark_fields(pcap_path: str) -> pd.DataFrame:
    """
    Use tshark to extract fields we care about.
    """
    fields = [
        'frame.time_epoch',
        'wlan.fc.type_subtype',
        'wlan_mgt.tag.ssid',           # some captures
        'wlan_mgt.ssid',               # others
        'wlan_radio.frequency',
        'wlan_radio.channel_width',
        'wlan.ta', 'wlan.ra'
    ]
    cmd = ['tshark', '-r', pcap_path, '-T', 'fields']
    for f in fields:
        cmd += ['-e', f]
    cmd += ['-E', 'separator=,', '-E', 'quote=d', '-E', 'header=y']

    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
    from io import StringIO
    df = pd.read_csv(StringIO(out))
    # Normalize columns
    if 'wlan_mgt.ssid' not in df.columns and 'wlan_mgt.tag.ssid' in df.columns:
        df['wlan_mgt.ssid'] = df.get('wlan_mgt.tag.ssid')
    return df


def _parse_pcap_with_pyshark(pcap_path: str) -> pd.DataFrame:
    """
    Fallback to pyshark parsing if tshark fields route fails (pyshark still needs tshark).
    """
    if pyshark is None:
        raise RuntimeError("pyshark not available; please install pyshark or export a CSV from Wireshark.")

    cap = pyshark.FileCapture(pcap_path, only_summaries=False)
    rows = []
    for pkt in cap:
        try:
            ts = float(pkt.sniff_timestamp)
            ssid = getattr(getattr(pkt, 'wlan_mgt', None), 'ssid', None)
            subtype = getattr(getattr(pkt, 'wlan', None), 'fc_type_subtype', None)
            freq = None
            width = None
            # Wireshark's wlan_radio fields are not always exposed; try best-effort
            radio = getattr(pkt, 'wlan_radio', None)
            if radio is not None:
                f = getattr(radio, 'frequency', None)
                freq = float(f) * 1e6 if f else None
                width = getattr(radio, 'channel_width', None)
            rows.append({
                'frame.time_epoch': ts,
                'wlan.fc.type_subtype': subtype,
                'wlan_mgt.ssid': ssid,
                'wlan_radio.frequency': freq if freq else '',
                'wlan_radio.channel_width': width if width else ''
            })
        except Exception:
            continue
    cap.close()
    return pd.DataFrame(rows)


def load_wifi_events(pcap: Optional[str], ws_csv: Optional[str]) -> List[Event]:
    if pcap:
        try:
            df = _run_tshark_fields(pcap)
        except Exception:
            df = _parse_pcap_with_pyshark(pcap)
    else:
        df = pd.read_csv(ws_csv)

    # Normalize types
    # Frequency may be in MHz or Hz; standardize to Hz first
    def norm_freq(x):
        if pd.isna(x) or x == '':
            return None
        f = float(str(x))
        return f * (1e6 if f < 1e5 else 1.0)  # if it's <100k, it's probably MHz

    df['freq_hz'] = df['wlan_radio.frequency'].apply(norm_freq) if 'wlan_radio.frequency' in df.columns else None

    # Derive band and width
    df['band'] = df['freq_hz'].apply(_band_from_freq) if 'freq_hz' in df.columns else None
    if 'wlan_radio.channel_width' in df.columns:
        df['width'] = df['wlan_radio.channel_width'].apply(_width_from_ws)
    else:
        df['width'] = None

    # Identify Beacon frames
    def is_beacon(row):
        st = str(row.get('wlan.fc.type_subtype', ''))
        # 8 == Beacon. CSV export sometimes writes text like 'Beacon'.
        return ('Beacon' in st) or (st.strip() == '8')

    wifi_events: List[Event] = []
    for _, r in df.iterrows():
        try:
            ts = float(r['frame.time_epoch'])
        except Exception:
            continue
        if not is_beacon(r):
            continue

        band = r.get('band')
        width = r.get('width') or '20'  # default to 20 if unknown (conservative)
        if band is None:
            continue

        label = f"wifi_beacon_{band}_{width}"
        meta = {
            'ssid': str(r.get('wlan_mgt.ssid', '') or ''),
            'freq_hz': str(r.get('freq_hz') or ''),
            'width_mhz': width,
        }
        wifi_events.append(Event(ts=ts, source='wifi', label=label, meta=meta))
    return wifi_events


def load_audio_events(wav_path: str,
                      band_low_hz: float = 18_000.0,
                      band_high_hz: float = 21_000.0,
                      peak_thresh_db: float = 12.0,
                      min_separation_s: float = 0.25) -> List[Event]:
    """
    Detect 'ultrasound' pings by energy peaks in a high-frequency band.

    peak_thresh_db: relative threshold above median band energy (dB).
    """
    audio, sr = sf.read(wav_path, always_2d=True)
    mono = audio.mean(axis=1)

    # STFT
    nfft = 4096
    hop = nfft // 4
    f, t, Z = stft(mono, fs=sr, nperseg=nfft, noverlap=nfft-hop, window='hann', padded=True, boundary='zeros')
    mag = np.abs(Z)

    # focus band
    band_idx = np.where((f >= band_low_hz) & (f <= band_high_hz))[0]
    if band_idx.size == 0:
        return []
    band_mag = mag[band_idx, :]
    band_energy = 20.0 * np.log10(np.maximum(1e-12, band_mag.mean(axis=0)))

    # robust threshold
    med = np.median(band_energy)
    peaks = np.where(band_energy > (med + peak_thresh_db))[0]

    # de-duplicate peaks by min distance
    events = []
    last_t = -1e9
    for idx in peaks:
        ts = float(t[idx])
        if ts - last_t >= min_separation_s:
            events.append(Event(
                ts=ts,  # relative to audio start; we align later if needed
                source='audio',
                label='ultra_18_21khz',
                meta={'peak_db': f"{band_energy[idx]:.1f}"}
            ))
            last_t = ts
    return events


def align_audio_to_wifi(audio_events: List[Event], wifi_events: List[Event]) -> List[Event]:
    """
    If audio timestamps are relative (0..N), but WiFi are epoch, we try a cheap alignment:
    We assume the first audio event happens near the first WiFi event (within a few seconds).
    You can override by passing --audio-offset if you know the offset.
    """
    if not audio_events or not wifi_events:
        return audio_events
    audio_t0 = min(e.ts for e in audio_events)
    wifi_t0 = min(e.ts for e in wifi_events)
    offset = wifi_t0 - audio_t0
    out = []
    for e in audio_events:
        out.append(Event(ts=e.ts + offset, source=e.source, label=e.label, meta=e.meta.copy()))
    return out


def find_motif(events: List[Event],
               motif: List[str],
               gap_s: float = 2.0) -> List[Tuple[Event, Event, Event]]:
    """
    Find occurrences of a 3-step motif with max gap between steps.
    Labels can be simplified tokens:
      wifi5_20 -> matches 'wifi_beacon_5g_20'
      wifi6_20 -> matches 'wifi_beacon_6g_20'
      ultra19  -> matches 'ultra_18_21khz'
    """
    def match(label: str, token: str) -> bool:
        token = token.lower()
        if token == 'ultra19':
            return label.startswith('ultra_')
        if token.startswith('wifi5'):
            return label.startswith('wifi_beacon_5g_') and (('_20' in label) if '20' in token else True)
        if token.startswith('wifi6'):
            return label.startswith('wifi_beacon_6g_') and (('_20' in label) if '20' in token else True)
        if token.startswith('wifi2'):
            return label.startswith('wifi_beacon_2g4_')
        return label == token

    ev = sorted(events, key=lambda e: e.ts)
    hits = []
    for i, a in enumerate(ev):
        if not match(a.label, motif[0]): 
            continue
        # find step 2 within gap
        j = i + 1
        while j < len(ev) and ev[j].ts - a.ts <= gap_s:
            if match(ev[j].label, motif[1]):
                b = ev[j]
                # find step 3 within gap
                k = j + 1
                while k < len(ev) and ev[k].ts - b.ts <= gap_s:
                    if match(ev[k].label, motif[2]):
                        hits.append((a, b, ev[k]))
                    k += 1
            j += 1
    return hits


def mine_top_triplets(events: List[Event], window_s: float = 3.0, top_k: int = 10):
    ev = sorted(events, key=lambda e: e.ts)
    counts: Dict[Tuple[str, str, str], int] = {}
    for i in range(len(ev)):
        for j in range(i+1, len(ev)):
            if ev[j].ts - ev[i].ts > window_s:
                break
            for k in range(j+1, len(ev)):
                if ev[k].ts - ev[i].ts > window_s:
                    break
                trip = (ev[i].label, ev[j].label, ev[k].label)
                counts[trip] = counts.get(trip, 0) + 1
    top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_k]
    return top


def main():
    ap = argparse.ArgumentParser(description="Timeline mapper for Wireshark + audio logs.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument('--pcap', help='Wireshark pcap/pcapng file (requires tshark/pyshark).')
    g.add_argument('--ws-csv', help='Wireshark exported CSV with specific columns.')

    ap.add_argument('--audio', required=True, help='Audio WAV file.')
    ap.add_argument('--audio-offset', type=float, default=None,
                    help='Seconds to add to audio timestamps to align with WiFi epoch. '
                         'If omitted, script estimates by aligning first events.')
    ap.add_argument('--out', default='timeline.csv', help='Output CSV of fused events.')

    ap.add_argument('--motif', default='wifi5_20,ultra19,wifi6_20',
                    help='3-step motif to search (comma-separated tokens).')
    ap.add_argument('--gap', type=float, default=2.0, help='Max seconds between motif steps.')
    ap.add_argument('--mine-top', type=int, default=0, help='If >0, also list top-K frequent triplets within 3s.')

    ap.add_argument('--ultra-low', type=float, default=18_000.0)
    ap.add_argument('--ultra-high', type=float, default=21_000.0)
    ap.add_argument('--ultra-thresh-db', type=float, default=12.0)
    ap.add_argument('--ultra-min-sep', type=float, default=0.25)

    args = ap.parse_args()

    wifi = load_wifi_events(args.pcap, args.ws_csv)
    audio = load_audio_events(
        args.audio,
        band_low_hz=args.ultra_low,
        band_high_hz=args.ultra_high,
        peak_thresh_db=args.ultra_thresh_db,
        min_separation_s=args.ultra_min_sep
    )

    if args.audio_offset is not None:
        aligned_audio = [Event(ts=e.ts + args.audio_offset, source=e.source, label=e.label, meta=e.meta) for e in audio]
    else:
        aligned_audio = align_audio_to_wifi(audio, wifi)

    all_events = sorted(wifi + aligned_audio, key=lambda e: e.ts)

    # Write timeline CSV
    with open(args.out, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['ts_epoch', 'source', 'label', 'meta'])
        for e in all_events:
            w.writerow([f"{e.ts:.6f}", e.source, e.label, e.meta])

    print(f"\nSaved fused timeline → {args.out}  (events: {len(all_events)})")

    # Motif search
    motif_tokens = [t.strip() for t in args.motif.split(',')]
    if len(motif_tokens) != 3:
        print("Motif must be 3 tokens (e.g., wifi5_20,ultra19,wifi6_20). Skipping.")
    else:
        hits = find_motif(all_events, motif_tokens, gap_s=args.gap)
        print(f"\nDetected motif {motif_tokens} within ≤{args.gap}s gaps: {len(hits)} occurrences")
        for idx, (a, b, c) in enumerate(hits[:25], 1):
            dt1 = b.ts - a.ts
            dt2 = c.ts - b.ts
            print(f"  #{idx:02d}  {a.ts:.3f} → {b.ts:.3f} (+{dt1:.2f}s) → {c.ts:.3f} (+{dt2:.2f}s)  "
                  f"[{a.label} → {b.label} → {c.label}]")
        if len(hits) > 25:
            print(f"  ...({len(hits)-25} more)")

    # Frequent triplets
    if args.mine_top > 0:
        top = mine_top_triplets(all_events, window_s=3.0, top_k=args.mine_top)
        print(f"\nTop {args.mine_top} triplets within 3s window:")
        for (a, b, c), cnt in top:
            print(f"  {cnt:3d} ×  [{a} → {b} → {c}]")

    print("\nDone.")
    

if __name__ == '__main__':
    main()
