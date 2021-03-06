# [本] Operating System Conectps

## 4. CPU Scheduling

> The most important concept in modern operatiing systems is undoubtedly "multiprogramming"

 * マルチプログラミングでCPUの利用率を上げて、ジョブのスルプートを向上させる
 
## 4.2 Scheduling Conepts

> A process is a program in execution

 * プロセスは状態を持つ
 * 実行によって状態を変化させる

### Process Control Block

 * task_struct, struct proc のこと
 * メモリに常駐する
 
## 4.2.2 Scheduling Queues

 * `ready queue`
   * run queue と一緒 (Bach本)。スケジューリング待ちのプロセス
 * `device queue`
   * デバイスのI/O待ちのキュー
   * Bach本だと、デバイス待ちのプロセスは高優先度を与えられてリソース解放を優先する、とある

## 4.2.3 Schedulers

 * スケジューラ (http://ja.wikipedia.org/wiki/スケジューリング)
   * shotr-term, medium-term, long-term
   * バッチジョブのシステムのことが分からない
   * タイムシェアリングなシステムには logn-term なスケジューラは実装されない
 * swap機能によって `reduce the degree of multiprogrammiing` マルチプログラミングの度合いを下げる
   * `overcommited` という単語がでてくる。メモリオーバーコミット

 * 各種スケジュールのアルゴリズムをハイブリッドにして、スケジューラを実装できる
   * Multi-Level Feedback で、優先度の高いキューは round rogin, 低いキューは FIFO するなど
   
   TODO: リアルタイムシステム, CFS
 
## 4.3.1 Perfomance Criteria

パフォーマンスの基準となる要素

 * CPU Utilization
 * Throughput
  * 時間あたりに処理したジョブ
 * Turnaround Time
  * ジョブが登録されて完了するまでの実時間
 * Waiting Time
 * Response Time
  * レスポンスを始めるまでの時間であり、完了する時間ではない。勘違いしやすい項目
  
その他 starvation の有無も評価すること
  
## 4.3.2 First-Come-First-Served (FIFO)

 * FCFS
 * 先に登録したジョブを先に処理。 cotext swtich はジョブ終了時のみ。
  * パフォーマンスは `quite poor`
  * `convoy effect` 衛船団効果?
  * 実行時間の長いジョブによって、他のジョブの完了が待たされてしまう
  * starvation はしない
  
アルゴリズムの評価は Turnaround Time の平均で評価されている点に注意
  
## 4.3.3 Shortest-Job-First

 * ジョブの実行時間が短いものを優先する
 * ただし、次のジョブの実行時間の予測は難しい
 * `exponential average` 指数平均(指数移動平均？） で計算

## 4.3.4 Priority

 * 優先度の高いジョブからスケジューリングする

 * p = 1 / T
  ( T は cpu burst. CPUの使用率が高いと優先度が下がる )

 * 優先度の数値が 0 に近いと、優先度が高いのか低いのか一般的な見解は無い様子
 * 優先度付けの内的要因
   * メモリ使用量
   * オープンしているファイルの数
   * I/O burst の割合
 * 優先度付けの外的要因
   * お支払い
   * 政策?

 * starvation する
   * 高プライオリティのプロセスがいつづける状態だと、低プライオリティのジョブが処理されない
   * CPU優先度を上げるクリティカル区間が長過ぎるとデバイスの割り込みを処理できない、も似た現象
     * `aging` によって優先度を変化させる
       * 長い時間システムに残っているジョブの優先度を、定期的に引き上げる
       * タイマ割り込みが必要?

 * 小話
> Rumor has it that when they closed down the 7094 at MIT in 1973,
>they found a low-priority job that had been submitted 1967 and had not yet been run
  
## 4.3.5 Preemptive Algorythms

 * FCFS は本質的に non-preemptive
 * priority scheduler を preemptive にすると...
   * 現在実行中のプロセスより高い優先度のプロセスがいた場合に preempt する実装にする

## 4.3.6 Round-Robin

 * ラウンドロビン
   * `time quantum` `time slice` を割り当てて、順番にCPU割当てする。優先度は考えない
   * `ready queue` (run queue) は 循環キューとして実装される
 
 /_/howm/images/Operating_System_Concepts.txt-20130121222944.png

 * quantum を使い切らないプロセスは I/O を発行、exit するなどし 自発的にCPUを解放する ( `releases the cpu voluntarily` )
 * quantum を超過するプロセスに対しては割り込みを起こしてOSに制御を返す
   * preempt されて、ready queue に戻される。次回のラウンドロビンを待つ

 * `context switch`
   * 古いプロセスのレジスタを全退避、新しいプロセスのレジスタを復帰、という処理を割り込んでやる必要がある
   * context switch の時間は pure overhead である
     * ジョブの内容とは全く関係ない、ということだろう
     * ready queue ( run queue ) で待つプロセスが多い場合に context switch しまくり
   * context switch の実装はハードウェア依存。
     * メモリのスピード、レジスタの数、特殊な命令があるかどうかなど

 * starvation が無い
 * 待ち時間はプロセス数に反比例する
   * プロセス数が増えるとタイムスライスが短くなる

## 4.3.7 Multi-Lvel Queues

 * 複数のキューを用意して、ジョブをクラス分けする。またそれぞれのキューに固定の優先度を持たせる
 * ジョブはキューに固定される。他のキューに移動しない

/_/howm/images/Operating_System_Concepts.txt-20130121222704.png

 * プライオリティじゃなくて各キューにタイムスライスを割り当てる実装も考えられる
 
## 4.3.8 Multi-Level Feedback Queues (多段フィードバックキュー)

Multi-Level Queues に、実行プロセスからのフィードバックを受け取るようにしたもの

 * CPUを使い過ぎたジョブは、低い優先度のキューに移動される
 * I/Oバウンド、対話型のプロセスは高い優先度のキューに移動される
 * 低い優先度でいつづけたプロセスは高い優先度のキューに移動される
 
実装が大変とのこと

Bach本には System V のスケジューラは "round rogin with multilevel feedback" を使ってると書いてある

## 5. Memory Management

> Memory is a large array of words or bytes, each with its own address

 * 今日 `load` を意識してコードを書いてる場面が無いなと思った
 
## 5.3 Resident Monitor

 * resident monitor (= kernel) のメモリはアドレスの低位置に配置するものが多い
   * 割り込みベクタが低位置にするものが多いから? 保護するのにちょうどいいんだろうか
     * 8006 は割り込みベクタをメモリの 0 ~ 1K の領域にセットする (「はじめて読む8086」)

 * `fence address`
   * プログラム ( not プロセス) のアドレスの範囲をハードウェアで限定する仕組み
   * 特権つきの命令でレジスタに登録しておく

## 5.3.2 Relocation

 * relocatable, 再配置可能なコード
   * コード内のアドレスが相対アドレスで管理される。コンパイラの仕事
   * `binding` 実メモリに配置すること

 * PDP-11 はユーザーモードのコードは高位置のアドレスに配置 => 低い方 (fence) に向かって伸びる

 * `relocation register`
   * `dynamic relocation`

> Notice that the user never sees the real physical addresses

 * 物理的なアドレスを意識しない
 * 物理的な特性に縛られず、論理的な特性にのみに従ってプログラムを記述できる
 
## 5.4 Swapping

 * `Backing Store`
   * swap device のことじゃろう
   * 容量が大きいけど転送速度が遅いストレージに swap 領域を確保するという考え方は共通

## 5.5 Fixed Partitions

## 5.5.1 Proctetion Hardware

 * プログラムのアドレスの上限 <=> 下限を制限するレジスタ
   * `Bounds registers` 上限のアドレスを下限のアドレスを絶対値で指定
     * 静的な再配置
   * `Base and limit registers` 基点となるアドレス+リミット値で指定
     * 動的な再配置
     * x86のセグメントの考え方もこれ segment base, segment limit

## 5.7 paging

 * 物理メモリは `frames` と呼ぶブロックに分解される
 * 論理メモリは `pages`  に分解される
   * pages => page table => frames でアドレスの変換をする
   
ページングはハードウェア依存の仕様。 (design of ... にも同様の記述がある)

 * `paging itself is a form of dynamic relocation`
   * ページングの考え方は動的再配置そのもの
   
## 5.7.6 Two Views of Memory

 * ページング
   * 論理アドレスと物理アドレスの分離。

## 5.8 Segmentation

 * セグメント機構。x86のやつ
   * 名前で参照する
   * 可変長の領域
     * 名前と長さをもつ領域、として抽象化

 * `segment base` , `segment limit`
  * 8006 だと セグメントベース, オフセットアドレス と呼ぶ
 * `segment table`
  * base と limit のペアの配列
  * メモリかレジスタ上に配置しておく
  * PDP-11/45
    * 8個のセグメントレジスタ
      * 3bitの segment number (base), 13bit の segment offset (limit) => 8K の領域
  * 8086
    * CS Code Segment
    * DS Data Segment
    * ES Extra Segment
    * SS Stack Segment
      * オフセットアドレスが16bit = 1セグメントで64KB

## 5.8.4 Protection and Sharing

 * `non-self-modifying`
   * コードセグメントは不変であるようにする => 複数プロセスで共有可能
   * TODO: コードセグメントを複数プロセスで共有した場合、共有が解除されるまで上書きができないのでは?
 * セグメント機構は外部断片化( `external fragmentation` )する
   * ページングと違ってセグメントの領域が可変長であるため。
   * 領域を確保するために `compaction` が必要

## 6. Virtual Memory

 * `demand paging`

## 6.1 Overlays

 * 仮想メモリの仕組みがないと、プロセスの論理アドレス分のメモリを常駐させておく必要がある
   * データ/テキストセグメントで参照/実行されない箇所のコードをメモリに置いておくのは無駄
 * `overlay`
   * MSXのフロッピーディスクの交換?
 * `dynamic loading`
   * 動的ロード、プラグイン、遅延読み込み、実行時ロード

どちらもユーザランド側で実装する類いのもの。OS側であれこれするもんじゃないらしい。

## 6.2 Demand Paging

## 6.5 Page Replacement Algorytms

 * `reference string` 参照文字列?
   * ページ管理のアルゴリズムを評価する際に使う文字列。擬似コード的な用法

## 6.5.1  FIFO

### Belady's anomaly

## 6.5.2 Optimal Replacement

 * OPT, MIN
 * 将来的に最も長く使われないページを再利用する
   * Optimal(=最も効率が良い)...が実際的なシステムでは 予想不可
   * アルゴリズムの評価をする際に比較対象として使う

## 6.5.3 Least Recently Used

LRUのアルゴリズムをどう実装するかが肝。
ハードウェアの仕組みを利用しないとコストが高い管理方法

 * カウンタでの実装
   * 時刻やカウンタで管理。ページを参照する都度更新する

 * スタックとして実装
   * スタックのトップが最近使ったページ、スタックの底が最古のページ 
   * スタックの途中のエントリを抜き差しできるように二重リンクリストで管理する
     * ページを抜く => スタックのトップにページを置く => ポインタ操作6回 => 若干コスト高い

 * `stack alogorythms`
   *
   
## 6.5.4 Second Chance Replacement

 * 参照ビットが落ちていれば再利用
 * 参照ビットが立っていれば参照bitを落とす
   * 次回の page replacement で再利用される(かもしれない) => second chance
   * 参照のポインタを循環キュー ( circular queue ) で管理
 * 最悪のケース
   * ページテーブルのページ全部が参照bit立っている => O(n)
   * FIFO と同じ挙動になる

 * LFU `Least Frequently Used`
   * ページの参照カウントが最も低いものを再利用する
   * プログラムの初期に頻繁に参照されて、後々あんまり使われなくなるページがずっと残る欠点
     * 定期的にカウンタをクリアする実装などで解決できる (コスト高そう)

 * MFU `Most Frequently Used`

LFU, MFU は実装コストが高い ( TODO: どういった点が? )

 * `reference bit`
   * ページ参照で立つbit。ハードウェアでサポート
 * `dirty bit`
   * ページ更新で立つbit。ハードウェアでサポート
   * dirty bit が立っているページはディスクから読み出された後に更新されているので、再利用するにはディスクに書き出す必要がある
   * dirty bit が立っていないページは I/O せずに再利用できる

 * {reference,dirty} bit
   * 両者を組み合わせて使う。 
   * reference, dirty 共にたっていないページ => 全く利用されていないページ => FIFOなりランダムに選んで再利用できる

## 6.6.4 Thrashing

 * Thrashing している状態 とは
   * => swap in/swap out が発生しまくりという状況
     * device queue で待つプロセスが多い
     * ready queue ( run queue ) で待つプロセスが少ない

## 6.6.5 Locality

  * ページフレームの locality = 局所性 が図解されている
    * 空間局所性
    * 時間局所性

  * サブルーチンの呼び出しで 新しい局所性を確保する
    * ローカル変数
    * サブルーチンを抜けると元の局所性?に戻る

  * locality に十分なページフレームが割り当てられていない 
   * => Thrashing の原因になる

ページフレームが足りてない場合でも 局所的なコードを実行できる分だけのページフレームが割り当てられていれば、 thrashing しない、というまとめ
## 6.7.2 I/O Interlock

### 下記の状態が起こらない様に設計をする必要がある

I/O用に獲得したバッファに、必ずページが当てられていなければいけない

 * プロセスα が I/O リクエストを出して、I/O device (I/O待ち）キュー で待つ。
 * 他のプロセスがページフォルトを起こす 
 * `global replcement` で `waiting` なプロセスαのバッファを swap out して、ページフォルトに利用する
 * プロセスα の I/O 割り込みが起こるが、他のプロセスにページ奪われている

### 解決策

 * swap out される可能性のあるユーザーランドのメモリで I/O しない
   * 常にカーネルのメモリとユーザーランドのメモリとでコピーする

    [I/O decice] <==copy==> [Kernel Buffer] <==copy==> [User Memory]

 * ページをメモリに lock する (bitをたてる)
   * mlock(2) ?
     `After an mlock call, the indicated pages will cause neither a non-resident page nor address-translation fault until they are unlocked.`
   * mlock できるサイズは RLIMIT_MEMLOCK で決まる
   * "wired" (確保中) に相当するんだろうか?

    $ ulimit -a
    -t: cpu time (seconds)         unlimited
    -f: file size (blocks)         unlimited
    -d: data seg size (kbytes)     unlimited
    -s: stack size (kbytes)        8192
    -c: core file size (blocks)    0
    -v: address space (kb)         unlimited
    -l: locked-in-memory size (kb) unlimited
    -u: processes                  266
    -n: file descriptors           256

 * 優先度の低いプロセスがフォールトしてページを獲得 , CPU 待ちに入る
   * 優先度の高いプロセスが、↑のページを奪う
     * 優先度の低いプロセスが running になると、再度フォールト
       * 無駄がある

 * ロック忘れするとページ利用できなくなるので注意 ( = kernel bug )
 
## 6.7.3 Page Size

適切なページサイズをどう選ぶか

 * ページサイズが小さいと...
  * locality を高められる
  * 必要な部分だけページングしやすい
  * fault の数が増える
    * レジスタの保存/復帰、ページの置換、ページテーブルの更新のコスト

 * ページサイズが大きい
  * I/O の効率が良い
  * いらん部分のページングを起こす
  * `internal fragmentation` しやすい。
   * プログラムの最後に割り当てられるページは必ず未使用の部分を抱える
 
## 6.7.4 Program Structure

Demmand Paging の仕組みを意識して アルゴリズムやデータ構造を選ぶ事で locality を高める

 * Demand Paging の仕組みはプログラム側からは意識しないようにデザインされている
   * メモリの性質を気にかける必要はない
   * なのだけど、 Demand Paging (システム) の性質を意識することで、パフォーマンス向上を図れる
     * よくある配列の配列 ( Array of Array ) のイテレートする順番を意識 => locality を高める
      * ページフォールトの数を減らす, working set を小さくする

```
      // ********@-------@-------@-------@
      int array[1024][1024];
      for(int i = 0; i < 1024; i++) {
        for (int j = 0; j < 1024; j++) {
          fprintf(stderr, "ixj %dx%d\n", i,j);
          array[i][j] = 1;
        }
      }

      // *-------@*------@*------@*-------*
      int array[1024][1024];
      for(int j = 0; j < 1024; j++) {
        for (int i = 0; i < 1024; i++) {
          fprintf(stderr, "ixj %dx%d\n", i,j);
          array[i][j] = 1;
        }
      }
```      

  * スタック
   * 参照が常にスタックトップなのでlocality が高い

  * ハッシュテープル
   * 参照が分散するので、 locality が低い

## 6.7.5 Storage Hirarchy

 * `cost per bit` bit単価
 * Multics
   * Singile Level Storage
   * ファイルの概念がなく、メモリの操作で透過的にファイルの操作ができる mmap 的な。
   * アドレス空間にファイルがマップされるので、空間が十分に大きい必要がある

# 11 Protection

## 11.8

> Mechanisms determine how to do something
> In contrast, policies decide what will be done

 * `<domain, object, { access rights }>`
 * `domain` は抽象的なコンセプトで、実現する方法はいろいろある
   * user単位。ユーザー変更が domain 遷移の操作になる
   * プロセス単位。プロセス間のメッセージ交換がドメイン遷移?
   * プロシージャ単位。

 * Unix ... file system
   * `Domain switching corresponds to changing the user identification temporarily`
   * setuid, seteuid がドメイン遷移

 * Multics ... a ring structure
   * Ring 0 ... Ring 7
   * Ring N +1 is subset of Ring N
   * call gate ? を呼び出し?
   * need-to-know principle を強制できない。
     * 高位のドメインが低位のドメインのオブジェクト全てにアクセス可能

/_/howm/images/Operating_System_Concepts.txt-20130127224236.png

 * Hydra
   * capability
 * Cambridge CAP System
   * capability
