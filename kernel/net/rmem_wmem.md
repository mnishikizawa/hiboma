## tcp_rmemについて (v4.15.7)

- net/ipv4/tcp_output.cのtcp_select_initial_window()

```
#define U16_MAX		((u16)~0U)
#define TCP_MAX_WSCALE		14U
typedef uint16_t u16;

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
```

- TCP Window Scaleオプションが有効だった場合、net.ipv4.tcp_rmem, net.core.rmem_max,広告ウインドウサイズを比較してWindow scaleの値を決める。最大値は14でサイズは512Mb

### TCP Window scale
- 3 Wayハンドシェイク時に決定され、TCP Optionで確認できる。これに関係ありそうなSACKのサポートもこの時に決定。
- ssの出力結果からも確認可能
