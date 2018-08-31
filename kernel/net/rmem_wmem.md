## rmemについて

- net/ipv4/tcp_output.cのtcp_select_initial_window()

```
(*rcv_wscale) = 0;
	if (wscale_ok) {
		/* Set window scaling on max possible window */
		space = max_t(u32, space, sock_net(sk)->ipv4.sysctl_tcp_rmem[2]);
		space = max_t(u32, space, sysctl_rmem_max);
		space = min_t(u32, space, *window_clamp);
		while (space > U16_MAX && (*rcv_wscale) < TCP_MAX_WSCALE) {
			space >>= 1;
			(*rcv_wscale)++;
		}
	}
