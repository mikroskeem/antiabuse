import httpClient
import json
import os
import osproc
import re
import streams
import strtabs
import strutils
import tables

# LANG=C /usr/bin/journalctl -afb -p info -n1 -t sshd -o cat
var sshMatches = {
  r"Failed (.+) for( invalid user)? (.*) from (.+) port (\d+) ssh2.*": """{"username": "$3", "ip": "$4", "port": $5}""",
  r"Invalid user (.*) from (.+) port (\d+)": """{"username": "$1", "ip": "$2", "port": $3}""",
  r"Connection closed by authenticating user (.*) (.+) port (\d+) \[preauth\]": """{"username": "$1", "ip": "$2", "port": $3}""",
}.newStringTable
var compiledSshMatches = initTable[string, Regex]()

when isMainModule:
  # Compile matches
  for match, _ in sshMatches.pairs():
    compiledSshMatches[match] = re(match)

  var messageChannel: Channel[JsonNode]
  messageChannel.open()

  var messagePostingThread = Thread[void]()
  createThread(messagePostingThread, proc() {.thread.} =
    while true:
      let msg = messageChannel.recv()
      if msg == nil:
         break

      let httpCl = httpClient.newHttpClient()
      httpCl.headers = httpClient.newHttpHeaders({"Content-Type": "application/json"})
      try:
        discard httpCl.postContent(os.getEnv("ANTIABUSE_ABUSERS_POST_URL", "http://127.0.0.1:8450/ssh_abusers"), body = $msg)
      except:
        let e = getCurrentException()
        let eMsg = getCurrentExceptionMsg()
        stderr.writeLine("Unable to POST abuser information: ", repr(e), ": ", eMsg)

    messageChannel.close()
  )

  let journalctlEnv = {"LANG": "C"}.newStringTable
  let process = osproc.startProcess(
    os.getEnv("ANTIABUSE_JOURNALCTL_PATH", "/usr/bin/journalctl"),
    workingDir = os.getHomeDir(),
    env = journalctlEnv,
    args = ["-afb", "-p", "info", "-n1", "-t", "sshd", "-o", "cat"]
  )
  let strm = osproc.outputStream(process)

  var line = ""
  while strm.readLine(line):
    block lineMatcher:
      for rawMatch, match in compiledSshMatches.pairs():
        if line.find(match) > -1:
          let replacement = sshMatches[rawMatch]
          let replaced = line.replacef(match, replacement)

          var jsonEntry: JsonNode
          try:
            jsonEntry = json.parseJson(replaced)
          except:
            stderr.writeLine("Broken json: ", replaced)
            break lineMatcher

          messageChannel.send(jsonEntry)
          break lineMatcher

      #echo %*{"error": "Failed to parse line", "line": line}
