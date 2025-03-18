## https://tools.ietf.org/html/rfc3501

import net, asyncnet, asyncdispatch, strutils, tables
export Port

const CRLF* = "\c\L"

type ImapCommandStatus* = enum
  icsContinue = -1
  icsOk
  icsBad
  icsNo

type ImapListener = proc(line: string)

type ImapClientBase*[SocketType] = ref object of RootObj
  socket*: SocketType
  ssl: bool
  tag: int

type ImapClient* = ImapClientBase[Socket]
type AsyncImapClient* = ImapClientBase[AsyncSocket]

proc newImapClient*(): ImapClient =
  ImapClient(socket: newSocket())

proc newAsyncImapClient*(): AsyncImapClient =
  AsyncImapClient(socket: newAsyncSocket())

when defined(ssl):
  proc newImapClient*(sslContext: SslContext): ImapClient =
    let s = newSocket()
    sslContext.wrapSocket(s)
    ImapClient(socket: s, ssl: true)

  proc newAsyncImapClient*(sslContext: SslContext): AsyncImapClient =
    let s = newAsyncSocket()
    sslContext.wrapSocket(s)
    AsyncImapClient(socket: s, ssl: true)

proc ssl*(client: ImapClientBase): bool =
  client.ssl

proc checkLine(client: ImapClientBase, tag, line: string): ImapCommandStatus =
  result = icsContinue

  var ind = 0
  while ind < tag.len:
    if tag[ind] != line[ind]:
      return
    ind.inc
  ind.inc

  case line[ind]
  of 'O':
    if line[ind + 1] == 'K':
      result = icsOk
  of 'B':
    if line[ind + 1] == 'A' and line[ind + 2] == 'D':
      result = icsBad
  of 'N':
    if line[ind + 1] == 'O':
      result = icsNo
  else:
    discard

proc genTag(client: ImapClientBase): string =
  result = $client.tag
  client.tag.inc

proc getData(
    client: ImapClient | AsyncImapClient, tag: string, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  while true:
    var line = (await client.socket.recvLine()).strip()
    result = client.checkLine(tag, line)

    when defined(debugImap):
      echo "IMAP GOT LINE: ", line

    if line.len > 0:
      if not listener.isNil:
        listener(line)

    if result != icsContinue:
      break

proc send(
    client: ImapClient | AsyncImapClient, cmd: string, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  let tag = client.genTag()
  let cmd = tag & " " & cmd & CRLF

  when defined(debugImap):
    echo "SEND CMD: ", cmd

  await client.socket.send(cmd)
  result = await client.getData(tag, listener)

proc connect*(
    client: ImapClient | AsyncImapClient,
    host: string,
    port: Port,
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  await client.socket.connect(host, port)
  result = await client.getData("*", listener)

proc capability*(
    client: ImapClient | AsyncImapClient, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("CAPABILITY", listener)

proc noop*(
    client: ImapClient | AsyncImapClient, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("NOOP", listener)

proc logout*(
    client: ImapClient | AsyncImapClient, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("LOGOUT", listener)

proc starttls*(
    client: ImapClient | AsyncImapClient, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("STARTTLS", listener)

proc authenticate*(
    client: ImapClient | AsyncImapClient,
    mechanism, data: string,
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  var cmd = "AUTHENTICATE " & mechanism
  if data.len > 0:
    cmd &= " " & data
  result = await client.send(cmd, listener)

proc login*(
    client: ImapClient | AsyncImapClient,
    username, password: string,
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("LOGIN " & username & " " & password, listener)

proc select*(
    client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("SELECT " & mailbox, listener)

proc examine*(
    client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("EXAMINE " & mailbox, listener)

proc create*(
    client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("CREATE " & mailbox, listener)

proc delete*(
    client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("DELETE " & mailbox, listener)

proc rename*(
    client: ImapClient | AsyncImapClient,
    oldname, newname: string,
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("RENAME " & oldname & " " & newname, listener)

proc subscribe*(
    client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("SUBSCRIBE " & mailbox, listener)

proc unsubscribe*(
    client: ImapClient | AsyncImapClient, mailbox: string, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("UNSUBSCRIBE " & mailbox, listener)

proc list*(
    client: ImapClient | AsyncImapClient,
    reference: string = "\"\"",
    mailbox: string = "\"*\"",
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("LIST " & reference & " " & mailbox, listener)

proc lsub*(
    client: ImapClient | AsyncImapClient,
    reference: string = "\"\"",
    mailbox: string = "\"*\"",
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("LSUB " & reference & " " & mailbox, listener)

type StatusItem* = enum
  siMessages = "MESSAGES"
  siRecent = "RECENT"
  siUidnext = "UIDNEXT"
  siUidvalidity = "UIDVALIDITY"
  siUnseen = "UNSEEN"

proc status*(
    client: ImapClient | AsyncImapClient,
    mailbox: string,
    items: set[StatusItem] = {siMessages},
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  var cmd = "STATUS " & mailbox & "("
  for item in items:
    cmd &= $item & " "
  cmd[cmd.len - 1] = ')'
  result = await client.send(cmd, listener)

proc append*(
    client: ImapClient | AsyncImapClient,
    mailbox, flags, msg: string,
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  var tag = client.genTag()
  await client.socket.send(
    tag & " " & " APPEND " & (
      if flags != "": mailbox & " (" & flags & ")" else: mailbox
    ) & " {" & $msg.len & "}"
  )

  let line = await client.socket.recvLine()

  if line.startsWith("+"):
    await client.socket.send(msg)
    await client.socket.send(CRLF)
    result = await client.getData(tag, listener)
  else:
    result = client.checkLine(tag, line)

proc check*(
    client: ImapClient | AsyncImapClient, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("CHECK", listener)

proc close*(
    client: ImapClient | AsyncImapClient, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("CLOSE", listener)

proc expunge*(
    client: ImapClient | AsyncImapClient, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("EXPUNGE", listener)

proc search*(
    client: ImapClient | AsyncImapClient, query: string, listener: ImapListener = nil
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("SEARCH " & query, listener)

proc fetch*(
    client: ImapClient | AsyncImapClient,
    mid: string,
    item: string = "FULL",
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("FETCH " & mid & " " & item, listener)

proc fetch*(
    client: ImapClient | AsyncImapClient,
    startmid, endmid: string,
    item: string = "FULL",
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("FETCH " & startmid & ":" & endmid & " " & item, listener)

proc store*(
    client: ImapClient | AsyncImapClient,
    mid: string,
    item, value: string,
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("STORE " & mid & " " & item & " " & value, listener)

proc store*(
    client: ImapClient | AsyncImapClient,
    startmid, endmid: string,
    item, value: string,
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send(
    "STORE " & startmid & ":" & endmid & " " & item & " " & value, listener
  )

proc copy*(
    client: ImapClient | AsyncImapClient,
    mid: string,
    mailbox: string,
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  result = await client.send("COPY " & mid & " " & mailbox, listener)

proc copy*(
    client: ImapClient | AsyncImapClient,
    startmid, endmid: string,
    mailbox: string,
    listener: ImapListener = nil,
): Future[ImapCommandStatus] {.multisync.} =
  result =
    await client.send("COPY " & startmid & ":" & endmid & " " & mailbox, listener)
