import json
import os
import osproc
import re
import streams
import strtabs
import strutils
import tables

import mmgeoip

let geoipDbV4 = mmgeoip.GeoIP("/usr/share/GeoIP/GeoIP.dat", mmgeoip.MEMORY_CACHE)
let geoipDbV6 = mmgeoip.GeoIP("/usr/share/GeoIP/GeoIPv6.dat", mmgeoip.MEMORY_CACHE)

# LANG=C /usr/bin/journalctl -afb -p info -n1 -t sshd -o cat
var sshMatches = {
  r"Failed (.+) for( invalid user)? (.*) from (.+) port (\d+) ssh2.*": """{"user": "$3", "ip": "$4", "port": $5}""",
  r"Invalid user (.*) from (.+) port (\d+)": """{"user": "$1", "ip": "$2", "port": $3}""",
  r"Connection closed by authenticating user (.*) (.+) port (\d+) \[preauth\]": """{"user": "$1", "ip": "$2", "port": $3}""",
}.newStringTable
var compiledSshMatches = initTable[string, Regex]()

when isMainModule:
  # Compile matches
  for match, _ in sshMatches.pairs():
    compiledSshMatches[match] = re(match)

  let journalctlEnv = {"LANG": "C"}.newStringTable
  let process = osproc.startProcess(
    "/usr/bin/journalctl",
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

          let address = jsonEntry{"ip"}.getStr()
          if strutils.contains(address, ":"):
            jsonEntry["country"] = json.newJString($geoipDbV6.country_code_by_addr(address))
          else:
            jsonEntry["country"] = json.newJString($geoipDbV4.country_code_by_addr(address))

          echo $jsonEntry
          break lineMatcher

      echo %*{"error": "Failed to parse line", "line": line}
