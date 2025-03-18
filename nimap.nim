import net, asyncnet, asyncdispatch, strutils, strformat, re, tables
export Port

const CRLF* = "\c\L"

type ImapCommandStatus* = enum
  icsContinue = -1
  icsOk
  icsBad
  icsNo

type ImapClientBase*[SocketType] = ref object of RootObj
  socket*: SocketType
  ssl: bool
  tag: int

type ImapClient* = ImapClientBase[Socket]
type AsyncImapClient* = ImapClientBase[AsyncSocket]

# Helper procs
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

proc genTag(client: ImapClientBase): string =
  result = $client.tag
  client.tag.inc

proc checkStatus(client: ImapClientBase, tag, line: string): ImapCommandStatus =
  if line.startsWith(tag):
    case line.split()[1]
    of "OK":
      return icsOk
    of "BAD":
      return icsBad
    of "NO":
      return icsNo
  icsContinue

proc readLiteral(
    client: ImapClient | AsyncImapClient, size: int
): Future[string] {.multisync.} =
  result = newString(size)
  var totalRead = 0
  while totalRead < size:
    let chunk = await client.socket.recv(min(size - totalRead, 4096))
    copyMem(addr result[totalRead], unsafeAddr chunk[0], chunk.len)
    totalRead += chunk.len

# Core commands
proc connect*(
    client: ImapClient | AsyncImapClient, host: string, port: Port
): Future[bool] {.multisync.} =
  await client.socket.connect(host, port)
  let greeting = await client.socket.recvLine()
  return greeting.startsWith("* OK")

proc login*(
    client: ImapClient | AsyncImapClient, username, password: string
): Future[bool] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} LOGIN {username} {password}{CRLF}")
  while true:
    let line = await client.socket.recvLine()
    if line.startsWith(tag):
      return client.checkStatus(tag, line) == icsOk

proc search*(
    client: ImapClient | AsyncImapClient, query: string
): Future[seq[string]] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} SEARCH {query}{CRLF}")

  var ids: seq[string]
  while true:
    let line = (await client.socket.recvLine()).strip()
    if line.startsWith("* SEARCH"):
      ids.add(line[8 ..^ 1].splitWhitespace())
    elif line.startsWith(tag):
      if client.checkStatus(tag, line) == icsOk:
        return ids
      else:
        return @[]

proc fetch*(
    client: ImapClient | AsyncImapClient, mid: string, item: string = "RFC822"
): Future[string] {.multisync.} =
  ## Fetches message content with proper literal handling using recv/recvLine
  let tag = client.genTag()
  await client.socket.send(&"{tag} FETCH {mid} {item}{CRLF}")

  var content: string
  var inLiteral = false
  var literalSize = 0
  let literalPattern = re(r"\{(\d+)\}$")  # Match {size} at end of line

  while true:
    if inLiteral:
      # Read literal content directly
      content.add(await client.readLiteral(literalSize))
      inLiteral = false
      
      # Read and check closing line
      let line = (await client.socket.recvLine()).strip()
      if line != ")":  # Handle unexpected format
        content.add(line & CRLF)
      continue

    let line = await client.socket.recvLine()
    if line.len == 0:
      continue

    if line.startsWith(tag):
      if client.checkStatus(tag, line) == icsOk:
        break
      else:
        return ""

    # Check for literal specification at end of line
    var matches: array[1, string]
    if line.find(literalPattern, matches) != -1:
      literalSize = parseInt(matches[0])
      inLiteral = true
      
      # Add prefix before literal marker
      let prefix = line[0 ..< line.find('{')]
      if prefix.len > 0:
        content.add(prefix.strip() & CRLF)
      continue

    # Handle continuation response
    if line.startsWith("+"):
      literalSize = parseInt(line[1..^1].strip())
      content.add(await client.readLiteral(literalSize))
      continue

    # Regular line processing
    content.add(line)

  return content

proc logout*(client: ImapClient | AsyncImapClient): Future[bool] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} LOGOUT{CRLF}")
  while true:
    let line = await client.socket.recvLine()
    if line.startsWith(tag):
      return client.checkStatus(tag, line) == icsOk

proc capability*(client: ImapClient | AsyncImapClient): Future[seq[string]] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} CAPABILITY{CRLF}")
  
  var caps: seq[string]
  while true:
    let line = (await client.socket.recvLine()).strip()
    if line.startsWith("* CAPABILITY"):
      caps = line[12..^1].splitWhitespace()
    elif line.startsWith(tag):
      return if client.checkStatus(tag, line) == icsOk: caps else: @[]

proc select*(client: ImapClient | AsyncImapClient, mailbox: string): Future[bool] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} SELECT {mailbox}{CRLF}")
  while true:
    let line = await client.socket.recvLine()
    if line.startsWith(tag):
      return client.checkStatus(tag, line) == icsOk

proc create*(client: ImapClient | AsyncImapClient, mailbox: string): Future[bool] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} CREATE {mailbox}{CRLF}")
  while true:
    let line = await client.socket.recvLine()
    if line.startsWith(tag):
      return client.checkStatus(tag, line) == icsOk

proc delete*(client: ImapClient | AsyncImapClient, mailbox: string): Future[bool] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} DELETE {mailbox}{CRLF}")
  while true:
    let line = await client.socket.recvLine()
    if line.startsWith(tag):
      return client.checkStatus(tag, line) == icsOk

proc list*(client: ImapClient | AsyncImapClient, reference: string = "", mailbox: string = "*"): Future[seq[string]] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} LIST {reference} {mailbox}{CRLF}")
  
  var folders: seq[string]
  while true:
    let line = (await client.socket.recvLine()).strip()
    if line.startsWith("* LIST"):
      folders.add(line)
    elif line.startsWith(tag):
      return if client.checkStatus(tag, line) == icsOk: folders else: @[]

proc expunge*(client: ImapClient | AsyncImapClient): Future[seq[string]] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} EXPUNGE{CRLF}")
  
  var expunged: seq[string]
  while true:
    let line = (await client.socket.recvLine()).strip()
    if line.startsWith("*"):
      expunged.add(line)
    elif line.startsWith(tag):
      return if client.checkStatus(tag, line) == icsOk: expunged else: @[]

proc store*(client: ImapClient | AsyncImapClient, mid: string, flags: string): Future[bool] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} STORE {mid} FLAGS {flags}{CRLF}")
  while true:
    let line = await client.socket.recvLine()
    if line.startsWith(tag):
      return client.checkStatus(tag, line) == icsOk

proc copy*(client: ImapClient | AsyncImapClient, mid: string, mailbox: string): Future[bool] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} COPY {mid} {mailbox}{CRLF}")
  while true:
    let line = await client.socket.recvLine()
    if line.startsWith(tag):
      return client.checkStatus(tag, line) == icsOk

proc noop*(client: ImapClient | AsyncImapClient): Future[bool] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} NOOP{CRLF}")
  while true:
    let line = await client.socket.recvLine()
    if line.startsWith(tag):
      return client.checkStatus(tag, line) == icsOk

proc status*(client: ImapClient | AsyncImapClient, mailbox: string): Future[Table[string, int]] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} STATUS {mailbox} (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN){CRLF}")
  
  var stats = initTable[string, int]()
  while true:
    let line = (await client.socket.recvLine()).strip()
    if line.startsWith("* STATUS"):
      let parts = line.split({' ', '('})[3..^1]
      for i in countup(0, parts.len-1, 2):
        stats[parts[i]] = parseInt(parts[i+1])
    elif line.startsWith(tag):
      if client.checkStatus(tag, line) == icsOk:
        return stats
      else:
        return initTable[string, int]()

proc close*(client: ImapClient | AsyncImapClient): Future[bool] {.multisync.} =
  let tag = client.genTag()
  await client.socket.send(&"{tag} CLOSE{CRLF}")
  while true:
    let line = await client.socket.recvLine()

    if line.startsWith(tag):
      return client.checkStatus(tag, line) == icsOk