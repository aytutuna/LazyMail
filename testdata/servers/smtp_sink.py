#!/usr/bin/env python3
"""SMTP sink for tests: accepts any mail and writes each message to a directory.

usage: smtp_sink.py DIR CERT KEY PLAIN_PORT TLS_PORT

AUTH PLAIN and LOGIN work for the fixed test users, STARTTLS is offered on the
plain port, and the second port speaks TLS from the first byte.
"""
import asyncio
import base64
import itertools
import ssl
import sys

USERS = {"alice": "alice-pass", "bob": "bob-pass"}
out_dir, cert, key, plain_port, tls_port = sys.argv[1:6]
counter = itertools.count(1)


async def readline(reader):
    data = await reader.readline()
    if not data:
        raise ConnectionError
    return data.decode("utf-8", "replace").rstrip("\r\n")


async def session(reader, writer, tls):
    def send(text):
        writer.write(text.encode() + b"\r\n")

    send("220 lazymail test sink ready")
    sender, rcpts, authed = None, [], False
    try:
        while True:
            cmd = await readline(reader)
            verb = cmd.split(" ", 1)[0].upper()
            if verb == "EHLO":
                send("250-sink")
                send("250-8BITMIME")
                send("250-SIZE 10485760")
                send("250-AUTH PLAIN LOGIN")
                if not tls:
                    send("250-STARTTLS")
                send("250 ENHANCEDSTATUSCODES")
            elif verb == "HELO":
                send("250 sink")
            elif verb == "STARTTLS" and not tls:
                send("220 go ahead")
                await writer.drain()
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(cert, key)
                await writer.start_tls(ctx)
                tls = True
                sender, rcpts, authed = None, [], False
            elif verb == "AUTH":
                parts = cmd.split(" ")
                if parts[1].upper() == "PLAIN":
                    if len(parts) > 2:
                        blob = parts[2]
                    else:
                        send("334 ")
                        await writer.drain()
                        blob = await readline(reader)
                    _, user, password = base64.b64decode(blob).decode().split("\0")
                else:
                    send("334 " + base64.b64encode(b"Username:").decode())
                    await writer.drain()
                    user = base64.b64decode(await readline(reader)).decode()
                    send("334 " + base64.b64encode(b"Password:").decode())
                    await writer.drain()
                    password = base64.b64decode(await readline(reader)).decode()
                authed = USERS.get(user) == password
                send("235 2.7.0 ok" if authed else "535 5.7.8 bad credentials")
            elif verb == "MAIL":
                sender, rcpts = cmd[10:].strip(), []
                send("250 2.1.0 ok")
            elif verb == "RCPT":
                rcpts.append(cmd[8:].strip())
                send("250 2.1.5 ok")
            elif verb == "DATA":
                if sender is None or not rcpts:
                    send("503 5.5.1 need MAIL and RCPT first")
                    await writer.drain()
                    continue
                send("354 end with <CRLF>.<CRLF>")
                await writer.drain()
                body = []
                while True:
                    row = await readline(reader)
                    if row == ".":
                        break
                    body.append(row[1:] if row.startswith("..") else row)
                n = next(counter)
                with open(f"{out_dir}/{n:04d}.eml", "w", newline="") as f:
                    f.write(f"X-Sink-From: {sender}\r\n")
                    f.write(f"X-Sink-To: {' '.join(rcpts)}\r\n")
                    f.write(f"X-Sink-Auth: {'yes' if authed else 'no'}\r\n")
                    f.write("\r\n".join(body) + "\r\n")
                send(f"250 2.0.0 queued as {n}")
                sender, rcpts = None, []
            elif verb == "RSET":
                sender, rcpts = None, []
                send("250 ok")
            elif verb == "NOOP":
                send("250 ok")
            elif verb == "QUIT":
                send("221 bye")
                await writer.drain()
                break
            else:
                send("502 5.5.2 not implemented")
            await writer.drain()
    except (ConnectionError, ssl.SSLError):
        pass
    finally:
        writer.close()


async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    plain = await asyncio.start_server(
        lambda r, w: session(r, w, False), "127.0.0.1", int(plain_port)
    )
    secure = await asyncio.start_server(
        lambda r, w: session(r, w, True), "127.0.0.1", int(tls_port), ssl=ctx
    )
    async with plain, secure:
        await asyncio.gather(plain.serve_forever(), secure.serve_forever())


asyncio.run(main())
