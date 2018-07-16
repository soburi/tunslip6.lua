verbose = 1
ipaddr = ""
netmask = ""
slipfd = 0
basedelay=0
delaymsec=0
startsec = 0
startmsec = 0
delaystartsec = 0
delaystartmsec = 0
timestamp = 0
flowcontrol=0
showprogress=0
flowcontrol_xonxoff=0

tundev = ""

devmtu = 1500

gettimeofday = require 'posix' . gettimeofday
time = require 'posix' . time 
localtime = require 'posix' . localtime 
strftime = require 'posix' . strftime
getopt = require 'posix'.getopt
errno = require 'posix'.errno
open = require 'posix'.open

tcflush = require 'posix'.tcflush
tcgetattr = require 'posix'.tcgetattr
tcsetattr = require 'posix'.tcsetattr

function err(no)
  io.stderr:write(errno(no))
  io.stderr:write("\n")
end

function ssystem(...)
  print(...)
  io.stdout:flush()
  return os.execute(...)
end

function get_in_addr(sa)
  return sa.addr
end

startsecs = 0
startmsecs = 0

function stamptime()
  local tv = gettimeofday()
  local msecs = tv.usec/1000
  local secs = tv.sec
  if startsecs ~= 0 then
    secs  = secs - startsecs
    msecs = msecs - startmsecs
    if msecs < 0 then
      secs = secs - 1
      msecs = msecs + 1000
    end
    io.stderr:write(string.format("%04u.%03u ", secs, msecs))
  else
    startsecs  = secs
    startmsecs = msecs
    t=time()
    tmp=localtime()
    timec = strftime("%T",tmp)
    io.stderr:write(string.format("\n%s ",timec))
  end
end

function is_sensible_string(s, len)
   for i=1,len do 
    if s[i] == '\0' or s[i] == '\r' or s[i] == '\n' or s[i] == '\t' then
      -- nothing to do
    elseif s[i] < ' ' or '~' < s[i] then
      return 0
    end
  end
  return 1
end

function serial_to_tun(inslip, outfd)
  -- static union {
  --   unsigned char inbuf[2000]
  --} uip
  inbufptr = 0
  ret = 0
  i = 0
  c = ''

--#ifdef linux
  ret = inslip:read()
  --ret = io.readfread(&c, 1, 1, inslip)
  if ret == -1 or ret == 0 then err(1, "serial_to_tun: read") end
  goto after_fread
--#endif

 ::read_more::
  if(inbufptr >= sizeof(uip.inbuf)) then
    if timestamp ~= 0 then stamptime() end
    io.stderr:write(string.format("*** dropping large %d byte packet\n",inbufptr))
    inbufptr = 0
  end
  ret = inslip:read()
--#ifdef linux
 ::after_fread::
--#endif
  if ret == -1 then
    err(1, "serial_to_tun: read")
  end
  if ret == 0 then
    clearerr(inslip)
    return
  end
  PROGRESS(".")
  if c == SLIP_END then
    if(inbufptr > 0) then
      if(uip.inbuf[0] == '!') then
        if(uip.inbuf[1] == 'M') then
          -- Read gateway MAC address and autoconfigure tap0 interface
          char macs[24]
          pos = 0
          for i=0, 16 do
            macs[pos++] = uip.inbuf[2 + i]
            if ((i & 1) == 1 && i < 14) then
              macs[pos++] = ':'
            end
          end

          if timestamp then stamptime() end
          macs[pos] = '\0'
          -- printf("*** Gateway's MAC address: %s\n", macs)
          fprintf(stderr,"*** Gateway's MAC address: %s\n", macs)
          if(timestamp) then stamptime() end
          ssystem("ifconfig %s down", tundev)
          if(timestamp) then stamptime() end
          ssystem("ifconfig %s hw ether %s", tundev, &macs[6])
          if(timestamp) then stamptime() end
          ssystem("ifconfig %s up", tundev)
        end
      elseif(uip.inbuf[0] == '?') then
        if(uip.inbuf[1] == 'P') then
          --/* Prefix info requested */
          struct in6_addr addr
          int i
          char *s = strchr(ipaddr, '/')
          if(s ~= nil) then
            *s = '\0'
          end
          inet_pton(AF_INET6, ipaddr, &addr)
          if(timestamp) then stamptime() end
          fprintf(stderr,"*** Address:%s => %02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
          ipaddr,
          addr.s6_addr[0], addr.s6_addr[1],
          addr.s6_addr[2], addr.s6_addr[3],
          addr.s6_addr[4], addr.s6_addr[5],
          addr.s6_addr[6], addr.s6_addr[7])
          slip_send(slipfd, '!')
          slip_send(slipfd, 'P')
          for i=0, 8 do
            --/* need to call the slip_send_char for stuffing */
            slip_send_char(slipfd, addr.s6_addr[i])
          end
          slip_send(slipfd, SLIP_END)
        end
--#define DEBUG_LINE_MARKER '\r'
      elseif(uip.inbuf[0] == DEBUG_LINE_MARKER) then
        fwrite(uip.inbuf + 1, inbufptr - 1, 1, stdout)
      elseif(is_sensible_string(uip.inbuf, inbufptr)) then
        if(verbose==1) then --  /* strings already echoed below for verbose>1 */
          if timestamp ~= 0 then stamptime() end
          fwrite(uip.inbuf, inbufptr, 1, stdout)
        end
      else
        if(verbose>2) then
          if (timestamp) stamptime()
          printf("Packet from SLIP of length %d - write TUN\n", inbufptr)
          if verbose>4 ~= 0 then
--#if WIRESHARK_IMPORT_FORMAT
--            printf("0000")
--        for(i = 0; i < inbufptr; i++) printf(" %02x",uip.inbuf[i])
--#else
            printf("         ")
            for i=0,inbufptr do
              printf("%02x", uip.inbuf[i])
              if((i & 3) == 3) then printf(" ") end
              if((i & 15) == 15) then printf("\n         ") end
            end
--#endif
            printf("\n")
          end
        end
        if(write(outfd, uip.inbuf, inbufptr) ~= inbufptr) then
          err(1, "serial_to_tun: write")
        end
      end
      inbufptr = 0
    end
    break
  elseif c == SLIP_ESC then
    if(fread(&c, 1, 1, inslip) ~= 1) then
      clearerr(inslip)
      -- /* Put ESC back and give up! */
      ungetc(SLIP_ESC, inslip)
      return
    end

    if c == SLIP_ESC_END then
      c = SLIP_END
      break
    elseif c == SLIP_ESC_ESC then
      c = SLIP_ESC
      break
    elseif c == SLIP_ESC_XON then
      c = XON
      break
    elseif c == SLIP_ESC_XOFF then
      c = XOFF
      break
    end
    --/* FALLTHROUGH */
  else
    uip.inbuf[inbufptr++] = c

    --/* Echo lines as they are received for verbose=2,3,5+ */
    --/* Echo all printable characters for verbose==4 */
    if((verbose==2) or (verbose==3) or (verbose>4)) then
      if(c=='\n') then
        if(is_sensible_string(uip.inbuf, inbufptr)) then
          if timestamp ~= 0 then stamptime() end
          fwrite(uip.inbuf, inbufptr, 1, stdout)
          inbufptr=0
        end
      end
    elseif verbose==4 then
      if c == 0 or c == '\r' or c == '\n' or c == '\t' or (c >= ' ' && c <= '~') then
        fwrite(&c, 1, 1, stdout)
        if c=='\n' then
          if(timestamp) then stamptime() end
        end
      end
    end

    break
  end

  goto read_more
end

function slip_send_char(fd, c)
  if c == SLIP_END then
    slip_send(fd, SLIP_ESC)
    slip_send(fd, SLIP_ESC_END)
    break
  elseif c == SLIP_ESC then
    slip_send(fd, SLIP_ESC)
    slip_send(fd, SLIP_ESC_ESC)
    break
  elseif c == XON then
    if(flowcontrol_xonxoff) then
      slip_send(fd, SLIP_ESC)
      slip_send(fd, SLIP_ESC_XON)
    else
      slip_send(fd, c)
    end
    break
  elseif c == XOFF then
    if(flowcontrol_xonxoff) then
      slip_send(fd, SLIP_ESC)
      slip_send(fd, SLIP_ESC_XOFF)
    else
      slip_send(fd, c)
    end
    break
  else
    slip_send(fd, c)
    break
  end
end


function slip_send(fd, c)
  if(slip_end >= sizeof(slip_buf)) then
    err(1, "slip_send overflow")
  end
  slip_buf[slip_end] = c
  slip_end++
end

function slip_empty()
  return (slip_end == 0)
end

function slip_flushbuf(fd)
  if(slip_empty()) then
    return
  end

  n = write(fd, slip_buf + slip_begin, (slip_end - slip_begin))

  if(n == -1 and errno ~= EAGAIN) then
    err(1, "slip_flushbuf write failed")
  elseif(n == -1) then
    PROGRESS("Q");		/* Outqueueis full! */
  else
    slip_begin += n
    if(slip_begin == slip_end) then
      slip_begin = slip_end = 0
    end
  end
end


function write_to_serial(outfd, inbuf)
  len = #inbuf
  int i

  if(verbose>2) then
    if (timestamp) then stamptime() end
    printf("Packet from TUN of length %d - write SLIP\n", len)
    if (verbose>4) then
--#if WIRESHARK_IMPORT_FORMAT
--      printf("0000")
--	  for(i = 0; i < len; i++) printf(" %02x", p[i])
--#else
      printf("         ")
      for i=0, len do
        printf("%02x", p[i])
        if((i & 3) == 3) then printf(" ") end
        if((i & 15) == 15) then printf("\n         ") end
      end
--#endif
      printf("\n")
    end
  end

  --/* It would be ``nice'' to send a SLIP_END here but it's not
  -- * really necessary.
  -- */
  --/* slip_send(outfd, SLIP_END); */

  --for(i = 0; i < len; i++) 
  for i=0, len do
    if p[i] == SLIP_END then
      slip_send(outfd, SLIP_ESC)
      slip_send(outfd, SLIP_ESC_END)
      break
    elseif p[i] == SLIP_ESC then
      slip_send(outfd, SLIP_ESC)
      slip_send(outfd, SLIP_ESC_ESC)
      break
    elseif p[i] == XON then
      if(flowcontrol_xonxoff) then
        slip_send(outfd, SLIP_ESC)
        slip_send(outfd, SLIP_ESC_XON)
      else
        slip_send(outfd, p[i])
      end
      break
    elseif p[i] == XOFF then
      if(flowcontrol_xonxoff) then
        slip_send(outfd, SLIP_ESC)
        slip_send(outfd, SLIP_ESC_XOFF)
      else
        slip_send(outfd, p[i])
      end
      break
    else
      slip_send(outfd, p[i])
      break
    end
  end
  slip_send(outfd, SLIP_END)
  PROGRESS("t")
end




inbuf = ""

function tun_to_serial(infd, outfd)
  inbuf = read(intfd, #inbuf)
  if(inbuf == nil or inbuf < 0) then err(1, "tun_to_serial: read") end

  return write_to_serial(outfd, uip.inbuf, size)
end

function stty_telos(fd)
  --struct termios tty
  --speed_t speed = b_rate
  --
  tty = posix.termios

  if(tcflush(fd, posix.TCIOFLUSH) == -1) then err(1, "tcflush") end

  if(tcgetattr(fd) == -1) then err(1, "tcgetattr") end

  --cfmakeraw(&tty)

  -- /* Nonblocking read. */
  tty.cc[VTIME] = 0
  tty.cc[VMIN] = 0
  if flowcontrol == 0 then
    tty.cflag = bit.bor(tty.cflag, posix.CRTSCTS)
  else
    tty.cflag = bit.bor(tty.cflag, bit.bnot(posix.CRTSCTS))
  end
  tty.iflag = bit.band(tty.iflag, bit.bnot(posix.IXON))
  if(flowcontrol_xonxoff)  then
    tty.iflag = bit.bor(tty.iflag, posix.IXOFF , posix.IXANY)
  else
    tty.iflag = bit.bor(tty.iflag, bit.band(bit.bnot(posix.IXOFF), bit.bnot(posix.IXANY)))
  end
  tty.cflag = bit.band(tty.cflag, bit.bnot(posix.HUPCL))
  tty.cflag = bit.band(tty.cflag, bit.bnot(posix.CLOCAL))

  --cfsetispeed(&tty, speed)
  --cfsetospeed(&tty, speed)

  if(tcsetattr(fd, posix.TCSAFLUSH, tty) == -1) then err(1, "tcsetattr") end

--#if 1
  --/* Nonblocking read and write. */
  if(fcntl(fd, posix.F_SETFL, posix.O_NONBLOCK) == -1) then err(1, "fcntl") end

  tty.cflag = bit.bor(tty.cflag, posix.CLOCAL)
  if(tcsetattr(fd, posix.TCSAFLUSH, tty) == -1) then err(1, "tcsetattr") end

  --i = TIOCM_DTR
  --if(ioctl(fd, TIOCMBIS, i) == -1) then err(1, "ioctl") end
--#endif

  usleep(10*1000)		--/* Wait for hardware 10ms. */

  --/* Flush input and output buffers. */
  if(tcflush(fd, TCIOFLUSH) == -1) then err(1, "tcflush") end
end


function devopen(dev, flags)
  open("/dev/" .. dev, flags)
end

function tun_alloc(dev, tap)
  struct ifreq ifr
  fd = 0
  err = 0

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) then
    perror("can not open /dev/net/tun")
    return -1
  end

  memset(&ifr, 0, sizeof(ifr))

  --/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
  -- *        IFF_TAP   - TAP device
  -- *
  -- *        IFF_NO_PI - Do not provide packet information
  -- */
  ifr.ifr_flags = bit.bor((tap and IFF_TAP or IFF_TUN) , IFF_NO_PI)
  if(*dev != 0) then
    strncpy(ifr.ifr_name, dev, IFNAMSIZ)
  end

  if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) then
    close(fd)
    fprintf(stderr, "can not tunsetiff to %s (flags=%08x): %s\n", dev, ifr.ifr_flags,
            strerror(errno))
    return err
  end

  -- /* get resulting tunnel name */
  strcpy(dev, ifr.ifr_name)
  return fd
end


function cleanup(void)
--#ifndef __APPLE__
  if (timestamp) then stamptime() end
  ssystem("ifconfig %s down", tundev)
--#ifndef linux
--  ssystem("sysctl -w net.ipv6.conf.all.forwarding=1")
--#endif
--  /* ssystem("arp -d %s", ipaddr); */
  if (timestamp) then stamptime() end
  ssystem("netstat -nr | awk '{ if ($2 == \"%s\") print \"route delete -net \"$1; }' | sh", tundev)
--#else
--  {
    itfaddr = strdup(ipaddr)
    prefix = index(itfaddr, '/')
    if (timestamp) then stamptime() end
    ssystem("ifconfig %s inet6 %s remove", tundev, ipaddr)
    if (timestamp) then stamptime() end
    ssystem("ifconfig %s down", tundev)
    if ( prefix != NULL ) then *prefix = '\0' end
    ssystem("route delete -inet6 %s", itfaddr)
    free(itfaddr)
--  }
--#endif
end

function sigcleanup(signo)
  io.stderr:write(string.format("signal %d\n", signo))
  os.exit(0) --			/* exit(0) will call cleanup() */
end

got_sigalarm = 0

function sigalarm(signo)
  got_sigalarm = 1
  return
end

function sigalarm_reset()
--#ifdef linux
--#define TIMEOUT (997*1000)
  local TIMEOUT = (997*1000)
--#else
--#define TIMEOUT (2451*1000)
--#endif
  ualarm(TIMEOUT, TIMEOUT)
  got_sigalarm = 0
end

function ifconf(tundev, ipaddr)
--#ifdef linux
  if (timestamp) then stamptime() end
  ssystem("ifconfig %s inet `hostname` mtu %d up", tundev, devmtu)
  if (timestamp) then stamptime() end
  ssystem("ifconfig %s add %s", tundev, ipaddr)

--/* radvd needs a link local address for routing */
--#if 0
--/* fe80::1/64 is good enough */
--  ssystem("ifconfig %s add fe80::1/64", tundev)
--#elif 1
--/* Generate a link local address a la sixxs/aiccu */
--/* First a full parse, stripping off the prefix length */
--  {
    char lladdr[40]
    char c, *ptr=(char *)ipaddr
    uint16_t digit,ai,a[8],cc,scc,i
    for(ai=0; ai<8; ai++) do
      a[ai]=0
    end
    ai=0
    cc=scc=0
    while(c=*ptr++) do
      if(c=='/') break
      if(c==':') then
        if(cc) then
          scc = ai
        end
        cc = 1
        if(++ai>7) then break end
      else
        cc=0
        digit = c-'0'
        if (digit > 9) then
          digit = 10 + (c & 0xdf) - 'A'
        end
        a[ai] = (a[ai] << 4) + digit
      end
    end
    -- /* Get # elided and shift what's after to the end */
    cc=8-ai
    for(i=0,<cc) do
      if ((8-i-cc) <= scc) then
        a[7-i] = 0
      else
        a[7-i] = a[8-i-cc]
        a[8-i-cc]=0
      end
    end
    sprintf(lladdr,"fe80::%x:%x:%x:%x",a[1]&0xfefd,a[2],a[3],a[7])
    if (timestamp) then stamptime() end
    ssystem("ifconfig %s add %s/64", tundev, lladdr)
--  }
--#endif /* link local */
--#elif defined(__APPLE__)
--  {
--	char * itfaddr = strdup(ipaddr)
--	char * prefix = index(itfaddr, '/')
--	if ( prefix != NULL ) {
--		*prefix = '\0'
--		prefix++
--	} else {
--		prefix = "64"
--	}
--    if (timestamp) stamptime()
--    ssystem("ifconfig %s inet6 mtu %d up", tundev, devmtu)
--    if (timestamp) stamptime()
--    ssystem("ifconfig %s inet6 %s add", tundev, ipaddr )
--    if (timestamp) stamptime()
--    ssystem("sysctl -w net.inet6.ip6.forwarding=1")
--    free(itfaddr)
--  }
--#else
--  if (timestamp) stamptime()
--  ssystem("ifconfig %s inet `hostname` %s mtu %d up", tundev, ipaddr, devmtu)
--  if (timestamp) stamptime()
--  ssystem("sysctl -w net.inet.ip.forwarding=1")
--#endif /* !linux */

  if (timestamp) then stamptime() end
  ssystem("ifconfig %s\n", tundev)
end


function main(argv)
  c = 0
  tunfd = 0
  maxfd = 0
  ret = 0
  rset = nil
  wset =nil

  inslip = nil
  siodev = nil
  host = nil
  port = nil
  prog = nil
  baudrate = -2
  ipa_enable = 0
  tap = 0
  slipfd = 0

  argc = #argv

  prog = argv[0]
  io.stdout:setvbuf('full', 0)

  local last_index = 1
  for c, optarg, optind in getopt(argv, "B:HILPhXM:s:t:v::d::a:p:T") do
    print(c)
    print(optind)
    last_index = optind
    if c == 'B' then
      baudrate = atoi(optarg)
      break

    elseif c == 'H' then
      flowcontrol=1
      break

    elseif c == 'X' then
      flowcontrol_xonxoff=1
      break

    elseif c == 'L' then
      timestamp=1
      break

    elseif c == 'M' then
      devmtu=atoi(optarg)
      if(devmtu < MIN_DEVMTU) then
        devmtu = MIN_DEVMTU
      end

    elseif c == 'P' then
      showprogress=1
      break

    elseif c == 's' then
      if(strncmp("/dev/", optarg, 5) == 0) then
        siodev = optarg + 5
      else 
        siodev = optarg
      end
      break

    elseif c == 'I' then
      ipa_enable = 1
      io.stderr:write("Will inquire about IP address using IPA=\n")
      break

    elseif c == 't' then
      if(strncmp("/dev/", optarg, 5) == 0) then
        strncpy(tundev, optarg + 5, sizeof(tundev))
      else
        strncpy(tundev, optarg, sizeof(tundev))
      end
      break

    elseif c == 'a' then
      host = optarg
      break

    elseif c == 'p' then
      port = optarg
      break

    elseif c == 'd' then
      basedelay = 10
      if optarg ~= 0 then basedelay = atoi(optarg) end
      break

    elseif c == 'v' then
      verbose = 2
      if optarg ~= 0 then verbose = atoi(optarg) end
      break

    elseif c == 'T' then
      tap = 1
      break

    --elseif c == '?' or c == 'h' 
    else
io.stderr:write(string.format("usage:  %s [options] ipaddress\n", prog))
io.stderr:write("example: tunslip6 -L -v2 -s ttyUSB1 fd00::1/64\n")
io.stderr:write("Options are:\n")
--#ifndef __APPLE__
--io.stderr:write(" -B baudrate    9600,19200,38400,57600,115200 (default),230400,460800,921600\n")
--#else
io.stderr:write(" -B baudrate    9600,19200,38400,57600,115200 (default),230400\n")
---#endif
io.stderr:write(" -H             Hardware CTS/RTS flow control (default disabled)\n")
io.stderr:write(" -I             Inquire IP address\n")
io.stderr:write(" -X             Software XON/XOFF flow control (default disabled)\n")
io.stderr:write(" -L             Log output format (adds time stamps)\n")
io.stderr:write(" -s siodev      Serial device (default /dev/ttyUSB0)\n")
io.stderr:write(" -M             Interface MTU (default and min: 1280)\n")
io.stderr:write(" -T             Make tap interface (default is tun interface)\n")
io.stderr:write(" -t tundev      Name of interface (default tap0 or tun0)\n")
io.stderr:write(" -v[level]      Verbosity level\n")
io.stderr:write("    -v0         No messages\n")
io.stderr:write("    -v1         Encapsulated SLIP debug messages (default)\n")
io.stderr:write("    -v2         Printable strings after they are received\n")
io.stderr:write("    -v3         Printable strings and SLIP packet notifications\n")
io.stderr:write("    -v4         All printable characters as they are received\n")
io.stderr:write("    -v5         All SLIP packets in hex\n")
io.stderr:write("    -v          Equivalent to -v3\n")
io.stderr:write(" -d[basedelay]  Minimum delay between outgoing SLIP packets.\n")
io.stderr:write("                Actual delay is basedelay*(#6LowPAN fragments) milliseconds.\n")
io.stderr:write("                -d is equivalent to -d10.\n")
io.stderr:write(" -a serveraddr  \n")
io.stderr:write(" -p serverport  \n")
      os.exit(1)
      break
    end
  end
  argc = argc - (last_index - 1)
  for i=0,last_index+1 do
    table.remove(argv, 1)
  end

  if(#argv ~= 2 and #argv ~= 3) then
    err(1, "usage: %s [-B baudrate] [-H] [-L] [-s siodev] [-t tundev] [-T] [-v verbosity] [-d delay] [-a serveraddress] [-p serverport] ipaddress", prog)
  end
  ipaddr = argv[1]
  io.stderr:write(string.format("argument ipaddr=%s", ipaddr))

  if(baudrate ~= -2) then --/* -2: use default baudrate */
    b_rate = select_baudrate(baudrate)
    if(b_rate == 0) then
      err(1, "unknown baudrate %d", baudrate)
    end
  end

  if(host ~= nil) then
    --struct addrinfo hints, *servinfo, *p
    --int rv
    --char s[INET6_ADDRSTRLEN]
    hints = posix.sys.socket.PosixAddrInfo

    if(port == nil) then
      port = "60001"
    end

    --memset(&hints, 0, sizeof hints)
    hints.family = AF_UNSPEC
    hints.socktype = SOCK_STREAM

    if((rv = getaddrinfo(host, port, hints)) ~= 0) then
      err(1, string.format("getaddrinfo: %s", gai_strerror(rv)))
    end

    --/* loop through all the results and connect to the first we can */
    --for(p = servinfo; p ~= nil; p = p->ai_next) {
      --if((slipfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) then
      --  perror("client: socket")
      --  continue
      --end

      --if(connect(slipfd, p->ai_addr, p->ai_addrlen) == -1) then
      --  close(slipfd)
      --  perror("client: connect")
      --  continue
      --end
      --break
    --}

    if p == nil then
      err(1, string.format("can't connect to ``%s:%s''", host, port))
    end

    fcntl(slipfd, F_SETFL, O_NONBLOCK)

    --inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
    --          s, sizeof(s))
    io.stderr:write(string.format("slip connected to ``%s:%s''\n", s, port))

    --/* all done with this structure */
    freeaddrinfo(servinfo)

  else
    if(siodev ~= nil) then
        slipfd = devopen(siodev, bit.bor(posix.O_RDWR, posix.O_NONBLOCK))
      if(slipfd == -1) then
        err(1, "can't open siodev ``/dev/%s''", siodev)
      end
    else
      siodevs = { "ttyUSB0", "cuaU0", "ucom0" } --/* linux, fbsd6, fbsd5 */
      for i=1, 3 do
        siodev = siodevs[i]
        print(siodev)
        slipfd = devopen(siodev,  bit.bor(posix.O_RDWR, posix.O_NONBLOCK))
        if(slipfd ~= -1) then
          break
        end
      end
      if(slipfd == -1) then
        err(1, "can't open siodev")
      end
    end
    if timestamp ~= 0 then stamptime() end
    io.stderr:write(string.format("********SLIP started on ``/dev/%s''\n", siodev))
    stty_telos(slipfd)
  end
  slip_send(slipfd, SLIP_END)
  inslip = fdopen(slipfd, "r")
  if(inslip == nil) then err(1, "main: fdopen") end

  tunfd = tun_alloc(tundev, tap)
  if(tunfd == -1) then err(1, "main: open /dev/tun") end
  if timestamp ~= 0 then stamptime() end
  io.stderr:write(string.format("opened %s device ``/dev/%s''\n", tap and "tap" or "tun", tundev))

  atexit(cleanup)
  signal(SIGHUP, sigcleanup)
  signal(SIGTERM, sigcleanup)
  signal(SIGINT, sigcleanup)
  signal(SIGALRM, sigalarm)
  ifconf(tundev, ipaddr)

  while true do
    maxfd = 0
    rset = 0
    --FD_ZERO(&rset)
    --FD_ZERO(&wset)

    if(got_sigalarm and ipa_enable) then
      --/* Send "?IPA". */
      slip_send(slipfd, '?')
      slip_send(slipfd, 'I')
      slip_send(slipfd, 'P')
      slip_send(slipfd, 'A')
      slip_send(slipfd, SLIP_END)
      got_sigalarm = 0
    end

    if(not slip_empty()) then --{		/* Anything to flush? */
      --FD_SET(slipfd, &wset)
    end

    --FD_SET(slipfd, &rset)	-- /* Read from slip ASAP! */
    if(slipfd > maxfd) then maxfd = slipfd end

    --/* We only have one packet at a time queued for slip output. */
    if(slip_empty()) then
      --FD_SET(tunfd, &rset)
      if(tunfd > maxfd) then maxfd = tunfd end
    end

    --ret = select(maxfd + 1, &rset, &wset, nil, nil)
    if(ret == -1 and errno ~= EINTR) then
      err(1, "select")
    elseif(ret > 0) then
      --if(FD_ISSET(slipfd, &rset)) then
      --  serial_to_tun(inslip, tunfd)
      --end

      --if(FD_ISSET(slipfd, &wset)) then
        slip_flushbuf(slipfd)
      --  if(ipa_enable) then sigalarm_reset() end
      --end

      --/* Optional delay between outgoing packets */
      --/* Base delay times number of 6lowpan fragments to be sent */
      if(delaymsec) then
        tv = gettimeofday() 
        dmsec=(tv.sec-delaystartsec)*1000+tv.usec/1000-delaystartmsec
        if(dmsec<0) then delaymsec=0 end
        if(dmsec>delaymsec) then delaymsec=0 end
      end
      if delaymsec==0 then
        --if(slip_empty() && FD_ISSET(tunfd, &rset)) then
          size=tun_to_serial(tunfd, slipfd)
          slip_flushbuf(slipfd)
          if(ipa_enable) then sigalarm_reset() end
          if(basedelay) then
            tv = gettimeofday() 
            delaymsec=basedelay
            delaystartsec =tv.sec
            delaystartmsec=tv.usec/1000
          end
        --end
      end
    end
  end
end
-- ssystem("ls", "-l")
-- stamptime()
-- stamptime()
--
main(arg)
