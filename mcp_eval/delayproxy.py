"""TCP proxy that adds a one-way delay of RTT/2 in each direction, to emulate wide-area round trips on one host.
usage: python delayproxy.py LISTEN_PORT TARGET_PORT RTT_MS
"""
import asyncio, sys

LISTEN, TARGET, RTT = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3]) / 1000.0


async def pipe(reader, writer):
    q = asyncio.Queue()

    async def pump():
        while True:
            t, data = await q.get()
            if data is None:
                break
            d = t + RTT / 2 - asyncio.get_running_loop().time()
            if d > 0:
                await asyncio.sleep(d)
            writer.write(data)
            await writer.drain()
        writer.close()
    task = asyncio.create_task(pump())
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            q.put_nowait((asyncio.get_running_loop().time(), data))
    finally:
        q.put_nowait((0, None))
        await task


async def handle(cr, cw):
    sr, sw = await asyncio.open_connection('127.0.0.1', TARGET)
    await asyncio.gather(pipe(cr, sw), pipe(sr, cw), return_exceptions=True)


async def main():
    srv = await asyncio.start_server(handle, '127.0.0.1', LISTEN)
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
