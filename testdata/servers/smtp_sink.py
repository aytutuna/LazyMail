#!/usr/bin/env python3
"""SMTP sink for tests: accepts any mail and writes each message to a directory.

usage: smtp_sink.py DIR CERT KEY PLAIN_PORT TLS_PORT

AUTH PLAIN and LOGIN work for the fixed test users, STARTTLS is offered on the
plain port, and the second port speaks TLS from the first byte.
"""
import asyncio
import base64
import itertools
import os
import ssl
import sys

out_dir, cert, key, plain_port, tls_port = sys.argv[1:6]
users_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users")
USERS = dict(
    line.split(":{PLAIN}", 1) for line in open(users_file).read().splitlines() if line
)
counter = itertools.count(1)


async def readline(reader):
    data = await reader.readline()
    if not data:
        raise ConnectionError
    return data.decode("utf-8", "replace").rstrip("\r\n")


async def read_data(reader):
    """Reads a message up to CRLF.CRLF as raw bytes and undoes dot-stuffing.

    Returns None when a line has a bare LF or CR, so a test can assert that
    the core never sends one.
    """
    lines = []
    bare = False
    while True:
        row = await reader.readuntil(b"\r\n")
        if row == b".\r\n":
            return None if bare else b"".join(lines)
        if b"\n" in row[:-2] or b"\r" in row[:-2]:
            bare = True
        lines.append(row[1:] if row.startswith(b"..") else row)


def address(cmd):
    # Keep "<addr>" and drop ESMTP parameters such as SIZE= and BODY=.
    arg = cmd.split(":", 1)[1].strip()
    end = arg.find(">")
    return arg[: end + 1] if arg.startswith("<") and end > 0 else arg.split(" ")[0]


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
                try:
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
                except (IndexError, ValueError):
                    send("501 5.5.2 malformed AUTH")
                    await writer.drain()
                    continue
                authed = USERS.get(user) == password
                send("235 2.7.0 ok" if authed else "535 5.7.8 bad credentials")
            elif verb == "MAIL":
                sender, rcpts = address(cmd), []
                send("250 2.1.0 ok")
            elif verb == "RCPT":
                rcpts.append(address(cmd))
                send("250 2.1.5 ok")
            elif verb == "DATA":
                if sender is None or not rcpts:
                    send("503 5.5.1 need MAIL and RCPT first")
                    await writer.drain()
                    continue
                send("354 end with <CRLF>.<CRLF>")
                await writer.drain()
                body = await read_data(reader)
                if body is None:
                    send("550 5.6.0 bare CR or LF in message")
                    sender, rcpts = None, []
                    await writer.drain()
                    continue
                n = next(counter)
                with open(f"{out_dir}/{n:04d}.eml", "wb") as f:
                    f.write(f"X-Sink-From: {sender}\r\n".encode())
                    f.write(f"X-Sink-To: {' '.join(rcpts)}\r\n".encode())
                    f.write(f"X-Sink-Auth: {'yes' if authed else 'no'}\r\n".encode())
                    f.write(b"\r\n" + body)
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
    except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
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
