from socket import *
import os
import sys
import struct
import time
import select
import binascii

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 3

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

GEO_ENABLED = False
geoCache = {}
geoCallTimes = []


def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = string[count+1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2
    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet(ID, seq):
    myChecksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, seq)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)
    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, ID, seq)
    packet = header + data
    return packet


def isPrivate(ip):
    try:
        octets = [int(x) for x in ip.split(".")]
    except ValueError:
        return True
    if octets[0] == 10 or octets[0] == 127:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 100 and 64 <= octets[1] <= 127:
        return True
    if octets[0] == 169 and octets[1] == 254:
        return True
    return False


def getGeoInfo(ip):
    if not GEO_ENABLED:
        return ("", "")
    if ip in geoCache:
        return geoCache[ip]
    if isPrivate(ip):
        geoCache[ip] = ("Private / Local network", "")
        return geoCache[ip]
    if not REQUESTS_AVAILABLE:
        return ("requests module not installed", "")

    now = time.time()
    while geoCallTimes and now - geoCallTimes[0] > 60:
        geoCallTimes.pop(0)
    if len(geoCallTimes) >= 45:
        time.sleep(60 - (now - geoCallTimes[0]) + 1)
        geoCallTimes.pop(0)

    try:
        url = ("http://ip-api.com/json/" + ip +
               "?fields=status,message,country,regionName,city,isp,org,as")
        response = requests.get(url, timeout=3)
        geoCallTimes.append(time.time())
        info = response.json()
        if info.get("status") != "success":
            result = ("Geolocation unavailable (%s)" % info.get("message", "no data"), "")
        else:
            place = [p for p in (info.get("city"), info.get("regionName"),
                                 info.get("country")) if p]
            org = info.get("org") or info.get("isp") or info.get("as") or "Unknown"
            result = (", ".join(place) if place else "Unknown location", org)
    except Exception as e:
        result = ("Geolocation lookup failed (%s)" % type(e).__name__, "")

    geoCache[ip] = result
    return result


def resolveHost(hostname):
    try:
        return hostname, gethostbyname(hostname)
    except gaierror:
        if not hostname.startswith("www."):
            alt = "www." + hostname
            try:
                addr = gethostbyname(alt)
                print("\nNote: %s has no A record, tracing %s instead." % (hostname, alt))
                return alt, addr
            except gaierror:
                pass
        raise


BANNER_WIDTH = 70


def askChoice(prompt, valid):
    while True:
        try:
            ans = input(prompt).strip()
        except EOFError:
            print("")
            return None
        if ans in valid:
            return ans
        print("  Invalid choice. Please enter one of: %s"
              % ", ".join(sorted(valid, key=lambda v: int(v))))


def askYesNo(prompt):
    while True:
        try:
            ans = input(prompt).strip().lower()
        except EOFError:
            print("")
            return False
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        print("  Invalid input. Please answer y or n.")


def askHost():
    while True:
        try:
            h = input("Enter host or IP: ").strip()
        except EOFError:
            print("")
            return None
        if not h:
            print("  Hostname cannot be empty. Please try again.")
            continue
        if any(c in h for c in " \t/\\?#"):
            print("  Invalid hostname. Enter a bare host such as example.com, not a URL.")
            continue
        try:
            resolved, addr = resolveHost(h)
            return resolved
        except gaierror:
            print("  Could not resolve '%s'. Check the spelling or your connection." % h)


def get_route(hostname):
    hostname, destAddr = resolveHost(hostname)
    print("")
    print("=" * BANNER_WIDTH)
    print(" Traceroute to %s (%s)" % (hostname, destAddr))
    print(" Max hops: %d  |  Probes per hop: %d  |  Timeout: %.1f s"
          % (MAX_HOPS, TRIES, TIMEOUT))
    if GEO_ENABLED:
        print(" Geolocation: ip-api.com (City, Region, Country + Organization)")
    print("=" * BANNER_WIDTH)
    print("")
    print(" Hop  %10s %10s %10s  %s" % ("RTT 1", "RTT 2", "RTT 3", "IP Address"))
    print("-" * BANNER_WIDTH)

    myID = os.getpid() & 0xFFFF
    seq = 0
    reachedDest = False

    for ttl in range(1, MAX_HOPS + 1):
        rtts = []
        hopAddr = None
        hopMessage = None

        for tries in range(TRIES):
            timeLeft = TIMEOUT
            icmp = getprotobyname("icmp")
            mySocket = socket(AF_INET, SOCK_RAW, icmp)
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            try:
                seq = (seq + 1) & 0x7FFF
                d = build_packet(myID, seq)
                mySocket.sendto(d, (destAddr, 0))
                t = time.time()

                while True:
                    startedSelect = time.time()
                    whatReady = select.select([mySocket], [], [], timeLeft)
                    howLongInSelect = (time.time() - startedSelect)
                    if whatReady[0] == []:
                        rtts.append(None)
                        break
                    recvPacket, addr = mySocket.recvfrom(1024)
                    timeReceived = time.time()

                    icmpHeader = recvPacket[20:28]
                    types, code, checksum_val, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

                    isOurs = False
                    if types in (11, 3):
                        if len(recvPacket) >= 56:
                            quoted = struct.unpack("bbHHh", recvPacket[48:56])
                            if quoted[3] == myID and quoted[4] == seq:
                                isOurs = True
                    elif types == 0:
                        if packetID == myID and sequence == seq:
                            isOurs = True

                    if not isOurs:
                        timeLeft = timeLeft - howLongInSelect
                        if timeLeft <= 0:
                            rtts.append(None)
                            break
                        continue

                    hopAddr = addr[0]
                    rtts.append((timeReceived - t) * 1000)

                    if types == 11:
                        pass
                    elif types == 3:
                        errorCodes = {
                            0: "Destination Network Unreachable",
                            1: "Destination Host Unreachable",
                            2: "Destination Protocol Unreachable",
                            3: "Destination Port Unreachable",
                            9: "Network Administratively Prohibited",
                            10: "Host Administratively Prohibited",
                            13: "Communication Administratively Prohibited",
                        }
                        hopMessage = errorCodes.get(code, "Destination Unreachable (code %d)" % code)
                        reachedDest = True
                    elif types == 0:
                        reachedDest = True
                    else:
                        hopMessage = "Unexpected ICMP type %d" % types
                    break

            except timeout:
                rtts.append(None)
                continue
            except error as e:
                print("  Socket error: %s" % e)
                rtts.append(None)
                continue
            finally:
                mySocket.close()

        line = " [%2d] " % ttl
        for rtt in rtts:
            line += "%10s " % ("*" if rtt is None else "%.3f ms" % rtt)
        if hopAddr is None:
            print(line + " Request timed out")
        else:
            print(line + " " + hopAddr)
            if GEO_ENABLED:
                location, org = getGeoInfo(hopAddr)
                print("       Location: %s" % location)
                if org:
                    print("       Org     : %s" % org)
            if hopMessage:
                print("       Status  : %s" % hopMessage)

        if reachedDest:
            print("\nTrace complete: reached %s (%s) in %d hops." % (hostname, destAddr, ttl))
            return
    print("\nTrace stopped: destination not reached within %d hops." % MAX_HOPS)


if __name__ == "__main__":
    presets = {
        "1": ("Google (USA)", "google.com"),
        "2": ("DLSU Canvas (Instructure)", "dlsu.instructure.com"),
        "3": ("DLSU Website (Philippines)", "dlsu.edu.ph"),
        "4": ("CSIRO (Australia)", "www.csiro.au"),
        "5": ("M1 Limited (Singapore)", "www.m1.com.sg"),
        "6": ("NII (Japan)", "www.nii.ac.jp"),
        "7": ("NASA (USA)", "www.nasa.gov"),
    }
    presetKeys = ("1", "2", "3", "4", "5", "6", "7")

    print("")
    print("=" * BANNER_WIDTH)
    print(" NSCOM02 MCO2 - Traceroute using ICMP")
    print("=" * BANNER_WIDTH)
    print("")
    print(" Select a host to trace:")
    print("")
    for key in presetKeys:
        print("   [%s]  %-28s %s" % (key, presets[key][0], presets[key][1]))
    print("")
    print("   [8]  Enter a host manually")
    print("   [9]  Trace the three required hosts (1-3)")
    print("  [10]  Trace all seven hosts (1-7)")
    print("")
    print("=" * BANNER_WIDTH)

    choice = askChoice(" Choice: ", set(presetKeys) | {"8", "9", "10"})
    if choice is None:
        sys.exit(0)

    if REQUESTS_AVAILABLE:
        GEO_ENABLED = askYesNo(" Enable IP geolocation for each hop? (y/n): ")
    else:
        print(" Note: the requests module is not installed, geolocation is disabled.")
        GEO_ENABLED = False

    if choice in presets:
        hosts = [presets[choice][1]]
    elif choice == "8":
        manual = askHost()
        if manual is None:
            sys.exit(0)
        hosts = [manual]
    elif choice == "9":
        hosts = [presets[k][1] for k in ("1", "2", "3")]
    else:
        hosts = [presets[k][1] for k in presetKeys]

    try:
        for host in hosts:
            try:
                get_route(host)
            except gaierror:
                print("\nCould not resolve %s. Check the hostname or your connection." % host)
            except error as e:
                print("\nSocket error for %s: %s" % (host, e))
                print("Raw sockets need administrator privileges. "
                      "Run this in an elevated terminal.")
                break
    except KeyboardInterrupt:
        print("\nTraceroute stopped by user.")
