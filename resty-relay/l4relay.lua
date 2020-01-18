require "string"

-- Openresty's tcp sockets are ok, but udp sockets, especially the
-- ngx.req.socket() ones, are annoyingly limited:
--  1. Instead of yielding on no data, raw socket receive()
--     just returns with "no more data". And this is one of the least
--     problem.
--  2. And there's this "socket busy" error for udp, contrary to what
--     the document said, receive() and send() does "block" each other,
--     which isn't full duplex at all. (tcp socket is full duplex)
--  3. What is ngx_stream_lua_socket_udp_buffer?
--     Why does every udp request read write to this freaking buffer?
--     Do you just know that I happen to have only one worker?
--     Guess I should've brought more fun to the party.
--  4. Although nginx stream module now can accept and proxy multiple udp
--     packets from one client in one connection, the lua module can only
--     see the first packet. (patched)
-- Wonder why I should spend much time on it. At least I get a
-- taste of Lua, which has its own quirks.

local tcp_max_buf = 1024
local tcp_busy_timeout = 200
local udp_real_host_timeout = 200
local udp_max_realhost_num = 10
local udp_poll_interval = 100

local function byte_not(n)
   return bit.band(bit.bnot(n), 255)
   -- return bit32.band(bit32.bnot(n), 255)
   -- return ~(n) & 255
end

local function rev_char(c)
   -- "@" is not changed
   if c >= 48 and c <= 57 then
      return 48 + (57 - c);
   elseif c >= 65 and c <= 90 then
      return 65 + (90 - c);
   elseif c >= 97 and c <= 122 then
      return 97 + (122 - c);
   end
   return c
end

local function rev_bytes(s)
   local bytes = {s:byte(1, s:len())}
   for i=1,s:len() do
      bytes[i] = rev_char(bytes[i])
   end
   return string.char(unpack(bytes))
end

local function data_is_real_host(data)
   return data:len() > 1 and
      data:len() == byte_not(data:byte(1)) + 1 and
      data:find("@")
end

local function parse_real_host(data)
   local at_pos = data:find("@")
   if not at_pos or at_pos == 1 or at_pos == data:len() then
      ngx.log(ngx.EMERG, "reqsock failed to split real host: "..data)
      return nil
   end
   local real_host = data:sub(1, at_pos - 1)
   local real_port_str = data:sub(at_pos + 1, data:len())
   local real_port = tonumber(real_port_str)
   return real_host, real_port
end

local function tcp_do_relay(fromsock, tosock, timeout)
   local last_recv_second = ngx.time()
   local buf_size = tcp_max_buf
   local next_buf_size = tcp_max_buf
   while true do
      local data, err, partial = fromsock:receive(buf_size)
      if not data then
	 if err == "timeout" then
	    local partial_len = partial:len()
	    if partial_len > 0 then
	       next_buf_size = partial_len
	       data = partial
	       goto send_to_upstream
	    end
	    local is_not_really_timeout = ngx.time() <
	       (last_recv_second + timeout / 1000)
	    if is_not_really_timeout then
	       next_buf_size = 1
	       goto continue_recv
	    else
	       return "from", err
	    end
	 else
	    return "from", err
	 end
      else
	 next_buf_size = math.min(next_buf_size * 2, tcp_max_buf)
      end
      ::send_to_upstream::
      do
	 last_recv_second = ngx.time()
	 local bytes, err = tosock:send(rev_bytes(data))
	 if not bytes then
	    return "to", err
	 end
      end
      ::continue_recv::
      if next_buf_size == 1 and buf_size ~= 1 then
	 fromsock:settimeout(timeout)
      elseif next_buf_size ~= 1 and buf_size == 1 then
	 fromsock:settimeouts(timeout, timeout, tcp_busy_timeout)
      end
      buf_size = next_buf_size
   end
end

local function tcp_from_downstream(reqsock, upsock, timeout)
   local dir, err = tcp_do_relay(reqsock, upsock, timeout)
   -- reqsock error or upsock timeout
   if dir == "from" or err == "timeout" then
      upsock:close()
   end
   if err == "close" then
      ngx.exit(ngx.OK)
   else
      ngx.exit(ngx.ERROR)
   end
end

local function tcp_from_upstream(reqsock, upsock, timeout)
   local dir, err = tcp_do_relay(upsock, reqsock, timeout)
   -- reqsock error or upsock timeout
   if dir == "to" or err == "timeout" then
      upsock:close()
   end
   if err == "close" then
      ngx.exit(ngx.OK)
   else
      ngx.exit(ngx.ERROR)
   end
end

local function tcp_relay_to_server(
      relay_addr, relay_port, real_addr, real_port, timeout)
   ngx.log(ngx.INFO, "tcp relay from "..ngx.var.remote_addr.."@"..
              ngx.var.remote_port.." to "..real_addr.."@"..real_port)
   local reqsock = assert(ngx.req.socket())
   reqsock:settimeout(timeout)
   local upsock = ngx.socket.tcp()
   local ok, err = upsock:connect(relay_addr, relay_port)
   if not ok then
      ngx.log(ngx.EMERG, "upsock failed to connect: "..
		 relay_addr.." "..relay_port.." "..err)
      ngx.exit(ngx.ERROR)
   end
   upsock:settimeout(timeout)

   -- send real host address length and address
   local real_host = rev_bytes(real_addr.."@"..real_port)
   local addr_len_byte = string.char(byte_not(real_host:len()))
   local real_host_data = addr_len_byte..real_host
   local bytes, err = upsock:send(real_host_data)
   if not bytes then
      upsock:close()
      ngx.log(ngx.EMERG, "upsock failed to send real host: "..
		 real_host.." "..err)
      ngx.exit(ngx.ERROR)
   end

   reqsock:settimeouts(timeout, timeout, tcp_busy_timeout)
   upsock:settimeouts(timeout, timeout, tcp_busy_timeout)

   ngx.thread.spawn(tcp_from_upstream, reqsock, upsock, timeout)
   tcp_from_downstream(reqsock, upsock, timeout)
end

local function tcp_relay_from_client(timeout)
   local reqsock = assert(ngx.req.socket())
   reqsock:settimeout(timeout)

   -- get real host address length
   local data, err, partial = reqsock:receive(1)
   if not data then
      ngx.log(ngx.EMERG, "reqsock failed to get real host length: "..err)
      ngx.exit(ngx.ERROR)
   end
   local addr_len_byte = byte_not(data:byte(1))

   -- get real host address
   local data, err, partial = reqsock:receive(addr_len_byte)
   if not data then
      ngx.log(ngx.EMERG, "reqsock failed to get real host: "..err)
      ngx.exit(ngx.ERROR)
   end
   local real_addr, real_port = parse_real_host(rev_bytes(data))
   if not real_addr or not real_port then
      ngx.log(ngx.EMERG, "reqsock failed to parse real port: ".. data)
      ngx.exit(ngx.ERROR)
   end
   ngx.log(ngx.INFO, "tcp relay from "..ngx.var.remote_addr.."@"..
              ngx.var.remote_port.." to "..real_addr.."@"..real_port)

   local upsock = ngx.socket.tcp()
   local ok, err = upsock:connect(real_addr, real_port)
   if not ok then
      ngx.log(ngx.EMERG, "upsock failed to connect: "..
		 real_addr.." "..real_port.." "..err)
      ngx.exit(ngx.ERROR)
   end

   reqsock:settimeouts(timeout, timeout, tcp_busy_timeout)
   upsock:settimeouts(timeout, timeout, tcp_busy_timeout)

   ngx.thread.spawn(tcp_from_upstream, reqsock, upsock, timeout)
   tcp_from_downstream(reqsock, upsock, timeout)
end

local function udp_poll_relay(
      reqsock, upsock, timeout, need_confirm_real_host)
   local last_recv_second = ngx.time()
   while true do
      if ngx.time() >= last_recv_second + timeout / 1000 then
	 -- ngx.log(ngx.EMERG, "udp_poll_relay 1")
	 break
      end
      while true do -- receive from reqsock like there's no tomorrow
	 local data, err = reqsock:receive()
	 if data then
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 2")
	    last_recv_second = ngx.time()
	    if data_is_real_host(data) then
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 3")
	       -- real_host_data from downstream
	       if need_confirm_real_host then
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 4")
		  reqsock:send(data)
	       end
	    else
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 5")
	       local ok, err = upsock:send(rev_bytes(data))
	       if not ok then
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 6")
		  ngx.log(ngx.EMERG, "udp_poll_relay upsock send failed: "..err)
		  return "upsock", err
	       end
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 6.6 "..data)
	    end
	 elseif err == "no more data" or err == "timeout" then
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 7")
	    break
	 else
	    ngx.log(ngx.EMERG, "udp_poll_relay reqsock receive failed: "..err)
	    return "reqsock", err
	 end
      end
      while true do -- receive from upsock like there's no tomorrow
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 8")
	 local data, err = upsock:receive()
	 if data then
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 9")
	    last_recv_second = ngx.time()
	    if not data_is_real_host(data) then
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 10")
	       -- real_host_data from upstream does nothing
	       local ok, err = reqsock:send(rev_bytes(data))
	       if not ok then
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 11")
		  ngx.log("udp_poll_relay reqsock send failed: "..err)
		  return "reqsock", err
	       end
	    end
	 elseif err == "timeout" then
	    -- ngx.log(ngx.EMERG, "udp_poll_relay 12")
	    break
	 else
	    ngx.log(ngx.EMERG, "udp_poll_relay upsock receive failed: "..err)
	    return "upsock", err
	 end
      end
   end
end

local function udp_relay_to_server(
      relay_addr, relay_port, real_addr, real_port, timeout)
   ngx.log(ngx.INFO, "udp relay from "..ngx.var.remote_addr.."@"..
              ngx.var.remote_port.." to "..real_addr.."@"..real_port)
   local reqsock = assert(ngx.req.socket())
   local upsock = ngx.socket.udp()
   local ok, err = upsock:setpeername(relay_addr, relay_port)
   if not ok then
      ngx.log(ngx.EMERG, "upsock failed to setpeername: "..
		 relay_addr.." "..relay_port.." "..err)
      ngx.exit(ngx.ERROR)
   end

   -- send real host address length and address
   local real_host = rev_bytes(real_addr.."@"..real_port)
   local addr_len_byte = string.char(byte_not(real_host:len()))
   local real_host_data = addr_len_byte..real_host

   upsock:settimeout(udp_real_host_timeout)
   local real_host_confirmed = false
   for i=1,udp_max_realhost_num  do
      local ok, err = upsock:send(real_host_data)
      if not ok then
	 goto continue_send
      end
      if i == udp_max_realhost_num then
	 upsock:settimeout(timeout)
      end
      local data, err = upsock:receive()
      if not data then
	 goto continue_send
      end
      real_host_confirmed = data_is_real_host(data)
      if real_host_confirmed then
	 break
      end
      ::continue_send::
   end
   if not real_host_confirmed then
      ngx.log(ngx.EMERG, "upsock failed to confirm real host: "..
		 relay_addr.." "..relay_port.." "..real_host)
      ngx.exit(ngx.ERROR)
   end

   reqsock:settimeout(udp_poll_interval)
   upsock:settimeout(udp_poll_interval)

   local dir, err = udp_poll_relay(reqsock, upsock, timeout, false)
   if dir == "reqsock" or err == "timeout" then
      upsock:close()
   end
   if err == "close" then
      ngx.exit(ngx.OK)
   else
      ngx.exit(ngx.ERROR)
   end
end

local function udp_relay_from_client(timeout)
   local reqsock = assert(ngx.req.socket())
   reqsock:settimeout(timeout)

   -- get real host address
   local real_host_confirmed = false
   local real_addr, real_port
   for i=1,udp_max_realhost_num  do
      local data, err = reqsock:receive()
      if not data then
	 if err == "no more data" then
	    ngx.sleep(udp_real_host_timeout / 1000)
	    goto continue_recv
	 else
	    ngx.log(ngx.EMERG, "reqsock failed to get real host data: "..err)
	    ngx.exit(ngx.ERROR)
	 end
      end
      if not data_is_real_host(data) then
	 goto continue_recv
      end
      ngx.log(ngx.EMERG, "reqsock real host data len: "..data:len())
      local ok, err = reqsock:send(data)
      if not ok then
	 ngx.log(ngx.EMERG, "reqsock failed to confirm real host data: "..err)
	 ngx.exit(ngx.ERROR)
      end
      local real_host_data = rev_bytes(data:sub(2, data:len()))
      real_addr, real_port = parse_real_host(real_host_data)
      if not real_addr or not real_port then
	 goto continue_recv
      else
	 real_host_confirmed = true
	 break
      end
      ::continue_recv::
   end
   if not real_host_confirmed then
      ngx.log(ngx.EMERG, "reqsock failed to confirm real host")
      ngx.exit(ngx.ERROR)
   end
   ngx.log(ngx.INFO, "udp relay from "..ngx.var.remote_addr.."@"..
              ngx.var.remote_port.." to "..real_addr.."@"..real_port)

   local upsock = ngx.socket.udp()
   local ok, err = upsock:setpeername(real_addr, real_port)
   if not ok then
      ngx.log(ngx.EMERG, "upsock failed to setpeername: "..
		 real_addr.." "..real_port.." "..err)
      ngx.exit(ngx.ERROR)
   end

   reqsock:settimeout(udp_poll_interval)
   upsock:settimeout(udp_poll_interval)

   local dir, err = udp_poll_relay(reqsock, upsock, timeout, true)
   if dir == "reqsock" or err == "timeout" then
      upsock:close()
   end
   if err == "close" then
      ngx.exit(ngx.OK)
   else
      ngx.exit(ngx.ERROR)
   end
end

return {
   tcp_relay_to_server = tcp_relay_to_server,
   tcp_relay_from_client = tcp_relay_from_client,
   udp_relay_to_server = udp_relay_to_server,
   udp_relay_from_client = udp_relay_from_client,
}
