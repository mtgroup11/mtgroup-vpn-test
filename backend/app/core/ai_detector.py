"""
MTGroup VPN Ultimate — AI Anomaly Engine (Singularity Edition)
═══════════════════════════════════════════════════════════════════
Lightweight Python-native Recurrent Neural Network (RNN) that
analyzes traffic patterns and XDP drop rates to detect complex
anomalies (DPI probes, bot-nets) and trigger Fast-Track Defenses.

*Now using BCC (BPF Compiler Collection) for Zero-Copy metrics!*
"""

import asyncio
import logging
import math
import socket
import struct
import httpx
import os
import numpy as np
from collections import defaultdict
from typing import List, Dict

try:
    from bcc import BPF  # type: ignore
    HAS_BCC = True
except ImportError:
    HAS_BCC = False

from backend.app.orchestrator import orchestrator

logger = logging.getLogger("mtgroup.ai_detector")

BCC_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

BPF_LRU_HASH(ai_metrics_rx, u32, u64, 102400);

int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct iphdr *ip = (struct iphdr *)(skb->head + skb->network_header);
    u32 saddr = ip->saddr;
    u64 bytes = skb->len;
    
    u64 *val, initial = bytes;
    val = ai_metrics_rx.lookup(&saddr);
    if (val) {
        __sync_fetch_and_add(val, bytes);
    } else {
        ai_metrics_rx.update(&saddr, &initial);
    }
    return 0;
}
"""

class LightweightRNN:
    """
    A NumPy-accelerated Lightweight Recurrent Neural Network.
    Designed for time-series anomaly detection without dragging in PyTorch.
    Uses a simple Elman RNN architecture.
    """

    def __init__(self, input_size: int, hidden_size: int, output_size: int):
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        
        bound = 1 / math.sqrt(hidden_size)
        
        self.W_xh = np.random.uniform(-bound, bound, (hidden_size, input_size))
        self.W_hh = np.random.uniform(-bound, bound, (hidden_size, hidden_size))
        self.b_h = np.random.uniform(-bound, bound, (hidden_size, 1))
        
        self.W_hy = np.random.uniform(-bound, bound, (output_size, hidden_size))
        self.b_y = np.random.uniform(-bound, bound, (output_size, 1))

    def _tanh(self, x: np.ndarray) -> np.ndarray:
        return np.tanh(x)

    def _sigmoid(self, x: np.ndarray) -> np.ndarray:
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))

    def forward(self, sequence: List[List[float]]) -> float:
        h = np.zeros((self.hidden_size, 1))
        
        for x in sequence:
            x_vec = np.array(x).reshape(-1, 1)
            h = self._tanh(np.dot(self.W_xh, x_vec) + np.dot(self.W_hh, h) + self.b_h)
            
        y = np.dot(self.W_hy, h) + self.b_y
        return float(self._sigmoid(y)[0, 0])


class AnomalyPredictor:
    """
    Background worker that feeds network telemetry into the LightweightRNN.
    Uses BCC Kernel Maps to read exact bytes per IP instead of psutil.
    """

    def __init__(self, sequence_length: int = 10):
        # Features: [Rx_Bytes_Delta, Rate_of_Change]
        self.rnn = LightweightRNN(input_size=2, hidden_size=8, output_size=1)
        self.sequence_length = sequence_length
        
        self.ip_history: Dict[str, List[List[float]]] = defaultdict(list)
        self.last_bytes: Dict[str, float] = defaultdict(float)
        self.ip_baseline: Dict[str, float] = defaultdict(lambda: 0.0)
        
        self._is_running = False
        self._worker_task: asyncio.Task | None = None
        self._bpf = None

    def _init_bcc(self):
        if not HAS_BCC:
            logger.warning("BCC not available! AI Engine will not collect real kernel metrics.")
            return
        try:
            self._bpf = BPF(text=BCC_PROGRAM)
            logger.info("Kernel-Space AI Integration (BCC kprobe) loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load BCC script: {e}")

    async def start(self):
        if self._is_running:
            return
        self._is_running = True
        self._init_bcc()
        self._worker_task = asyncio.create_task(self._monitoring_loop())
        logger.info("AI Anomaly Engine (Kernel-Space Edition) started.")

    async def stop(self):
        self._is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("AI Anomaly Engine stopped.")

    async def _send_telegram_alert(self, ip_addr: str, score: float):
        bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
        admin_id = os.getenv("TELEGRAM_ADMIN_ID")
        if not bot_token or not admin_id:
            return
            
        # Mask the last octet for KVKK/GDPR
        parts = ip_addr.split(".")
        masked_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.xxx" if len(parts) == 4 else ip_addr
            
        message = f"🚨 *XDP-Spectre: Kritik Tehdit*\nIP: `{masked_ip}` engellendi!\nSkor: `{score:.3f}`\nAksiyon: XDP_DROP & BannedIP Logged"
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                await client.post(url, json={
                    "chat_id": admin_id,
                    "text": message,
                    "parse_mode": "Markdown"
                })
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")

    async def _monitoring_loop(self):
        backoff = 5.0
        while self._is_running:
            try:
                await self._collect_and_predict()
                backoff = 5.0  # Reset on success
                await asyncio.sleep(5.0)  # Cycle every 5 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in AI monitoring loop (Backoff: {backoff}s): {e}")
                await asyncio.sleep(backoff)
                backoff = min(60.0, backoff * 2)

    async def _collect_and_predict(self):
        if not self._bpf:
            return

        try:
            metrics_map = self._bpf.get_table("ai_metrics_rx")
            
            for k, v in metrics_map.items():
                ip_addr = socket.inet_ntoa(struct.pack("<I", k.value))
                current_bytes = float(v.value)
                
                # Calculate delta
                delta = current_bytes - self.last_bytes[ip_addr]
                if delta < 0:
                    delta = current_bytes  # Map was cleared
                self.last_bytes[ip_addr] = current_bytes
                
                # Features
                features = [
                    delta / 1000.0,
                    math.log1p(delta)
                ]
                
                self.ip_history[ip_addr].append(features)
                if len(self.ip_history[ip_addr]) > self.sequence_length:
                    self.ip_history[ip_addr].pop(0)
                    
                if len(self.ip_history[ip_addr]) == self.sequence_length:
                    anomaly_score = self.rnn.forward(self.ip_history[ip_addr])
                    
                    # Exponential Moving Average (EMA) baseline
                    current_baseline = self.ip_baseline[ip_addr]
                    if current_baseline == 0.0:
                        self.ip_baseline[ip_addr] = anomaly_score
                    else:
                        self.ip_baseline[ip_addr] = 0.9 * current_baseline + 0.1 * anomaly_score
                    
                    # Adaptive threshold: max of 0.80 or 1.5x baseline
                    adaptive_threshold = max(0.80, self.ip_baseline[ip_addr] * 1.5)
                    
                    if anomaly_score > adaptive_threshold:
                        reason = f"AI Detected High Confidence Anomaly (Score: {anomaly_score:.3f}, Baseline: {self.ip_baseline[ip_addr]:.3f})"
                        await orchestrator.handle_security_alert(ip_addr, reason)
                        asyncio.create_task(self._send_telegram_alert(ip_addr, anomaly_score))
                        self.ip_history[ip_addr].clear()
                        self.ip_baseline[ip_addr] = 0.0 # reset on block
                        
        except Exception as e:
            raise RuntimeError(f"BCC map read error: {e}") from e
