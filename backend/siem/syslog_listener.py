"""
Real syslog listener — UDP + TCP.
Receives logs from Linux servers, firewalls, network devices.
Enable: set CYBERNEST_SYSLOG_ENABLED=true in .env
"""
import asyncio, threading
from loguru import logger
from core.database import SessionLocal
from siem.ingest import ingest_log
from core.config import settings

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
    def connection_made(self, transport):
        self.transport = transport
        logger.info(f"[SYSLOG] UDP ready on :{settings.SYSLOG_UDP_PORT}")
    def datagram_received(self, data, addr):
        raw = data.decode("utf-8", errors="replace").strip()
        if not raw: return
        threading.Thread(target=self._process, args=(raw, addr[0]), daemon=True).start()
    def _process(self, raw, src_ip):
        if src_ip not in raw: raw = f"{raw} [from:{src_ip}]"
        db = SessionLocal()
        try: ingest_log(db, raw, self.tenant_id)
        except Exception as e: logger.error(f"[SYSLOG UDP] {e}")
        finally: db.close()

class SyslogTCPServer:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
    async def handle(self, reader, writer):
        src_ip = writer.get_extra_info("peername", ("unknown",))[0]
        try:
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=300)
                if not line: break
                raw = line.decode("utf-8", errors="replace").strip()
                if not raw: continue
                if src_ip not in raw: raw = f"{raw} [from:{src_ip}]"
                db = SessionLocal()
                try: ingest_log(db, raw, self.tenant_id)
                except Exception as e: logger.error(f"[SYSLOG TCP] {e}")
                finally: db.close()
        except (asyncio.TimeoutError, Exception):
            pass
        finally:
            writer.close()

async def start_syslog_listeners(tenant_id: int = None):
    loop = asyncio.get_event_loop()
    try:
        await loop.create_datagram_endpoint(
            lambda: SyslogUDPProtocol(tenant_id),
            local_addr=("0.0.0.0", settings.SYSLOG_UDP_PORT))
        logger.info(f"[SYSLOG] UDP on 0.0.0.0:{settings.SYSLOG_UDP_PORT}")
    except Exception as e:
        logger.error(f"[SYSLOG] UDP bind failed: {e}")
    try:
        tcp = SyslogTCPServer(tenant_id)
        server = await asyncio.start_server(tcp.handle, "0.0.0.0", settings.SYSLOG_TCP_PORT)
        logger.info(f"[SYSLOG] TCP on 0.0.0.0:{settings.SYSLOG_TCP_PORT}")
        async with server: await server.serve_forever()
    except Exception as e:
        logger.error(f"[SYSLOG] TCP bind failed: {e}")
