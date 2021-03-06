# UNIX Domain Socket

 * ハードウェア割り込みが無い
 * SOFTIRQ も無い
 * BSD層と proto_ops の実装だけ追えば理解できるので易しめ ...
 * pipe との違い
   * 只のデータストリームを流すだけの pipe に対して SOCK_STREAM, SOCK_DGRAM で扱える

## TODO

 * kiocb, sock_iocb でのデータ転送
 * unix_stream_recvmsg の MSG_WAITALL

## backlog のサイズ

backlog + 1 のソケットを sk_receive_queue にいれて CONNECTING で待たせる

 * `listen(sock, 0)` => バックログのサイズ 1
 * `listen(sock, 1)` => バックログのサイズ 2
 * ...

数字の計算をうっかり間違えないように :)

```c 
static inline int unix_recvq_full(struct sock const *sk)
{
	return skb_queue_len(&sk->sk_receive_queue) > sk->sk_max_ack_backlog;
}
``` 

## AF_UNIX + SOCK_STREAM の backlog, 未 accept のソケット

netstat の結果から読み取れる内容

 * connect(2) して unix_recvq_full で溢れたソケットは `LISTENING の ref count - 2` で数が出る
 * connect(2) できて accept(2) されていないソケットは CONNECTING
   * inode がふられていない
   * sk_receive_queue で backlog 扱いのソケット
 
```
unix  7      [ ACC ]     STREAM     LISTENING     67612  /tmp/unix.sock # 5個のソケットが sk_receive_queue から溢れてる
unix  2      [ ]         STREAM     CONNECTING    0      /tmp/unix.sock # 1個のソケットが backlog 
unix  2      [ ]         STREAM     CONNECTED     67614  /tmp/unix.sock
```

該当の処理をしているコードは以下の通り。 sock->proto->connect からの呼び出しを受ける unix_stream_connect

```c
static int unix_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			       int addr_len, int flags)
{
restart:
	/*  Find listening sock. */
    // ここで参照カウントが上がる
	other = unix_find_other(net, sunaddr, addr_len, sk->sk_type, hash, &err);
	if (!other)
		goto out;


// ...

    // sk_receive_queue が溢れているかどうか
	if (unix_recvq_full(other)) {
		err = -EAGAIN;
		if (!timeo)
			goto out_unlock;

        // サーバから起床させてもらうのを待つので
        // waitqueue で待つ
		timeo = unix_wait_for_peer(other, timeo);

		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			goto out;
		sock_put(other);
		goto restart;
	}
```

## connect(2) と setsockopt(2) の SO_SNDTIMEO のタイムアウト

setsockopt で SO_SNDTIMEO を指定すると connect のタイムアウトを指定できる

 * setsockopt は sk->sk_sndtimeo にタイムアウトをセットしている
 * sock_sndtimeo でタイムアウト値読み取る

次の検証用コードで connect(2) タイムアウトを検証できる

#### 検証用クライアント

```c
#if 0
#!/bin/bash
CFLAGS="-O2 -std=gnu99 -W -Wall -fPIE -D_FORTIFY_SOURCE=2"
o=`basename $0`
o=".${o%.*}"
gcc ${CFLAGS} -o $o $0 && ./$o $*; exit
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <err.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

int main()
{
	int sock;
	struct sockaddr_un addr;
	bzero(&addr, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "/tmp/unix.sock");

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket");
		exit(1);
	}

	struct timeval tv;
	tv.tv_sec  = 100.;
	tv.tv_usec = 0;

	if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv))) {
		perror("setsockopt");
	};

	/* バックログ (sock->sk_recvqueue が溢れている際に) ブロックする */
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("connect");
		exit(1);
	}

	fprintf(stderr, "connected\n");

	char buffer[128];
	if (recv(sock, buffer, 128, 0) == -1) {
		perror("recv");
	}
	
	exit(0);
}
```

#### 適当なサーバ

```c
#if 0
#!/bin/bash
CFLAGS="-O2 -std=gnu99 -W -Wall -fPIE -D_FORTIFY_SOURCE=2"
o=`basename $0`
o=".${o%.*}"
gcc ${CFLAGS} -o $o $0 && ./$o $*; exit
#endif

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

int main(void)
{
	struct sockaddr_un address;
	int socket_fd;
	
	socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(socket_fd < 0) {
		printf("socket() failed\n");
		return 1;
	}

	unlink("/tmp/unix.sock");

	/* start with a clean address structure */
	memset(&address, 0, sizeof(struct sockaddr_un));

	address.sun_family = AF_UNIX;
	snprintf(address.sun_path, 50, "/tmp/unix.sock");

	if(bind(socket_fd, (struct sockaddr *)&address, sizeof(struct sockaddr_un)) != 0) {			printf("bind() failed\n");
		return 1;
	}

	/* backlog + 1 をブロックする */
	if(listen(socket_fd, 0) != 0) {
		printf("listen() failed\n");
		return 1;
	}

	struct sockaddr_un client;
	socklen_t addrlen;
	memset(&client, 0, sizeof(struct sockaddr_un));
		
	accept(socket_fd, (struct sockaddr *)&client, &addrlen);
	
	pause();
	return 0;
}
```