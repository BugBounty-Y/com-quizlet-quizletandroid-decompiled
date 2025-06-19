package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.os.RemoteException;
import android.os.SystemClock;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.uF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2695uF implements InterfaceC2005eF, W {
    public static final Map V;
    public static final C1832aG W;
    public int A;
    public boolean B;
    public boolean C;
    public boolean D;
    public int E;
    public boolean F;
    public long G;
    public long H;
    public boolean I;
    public int J;
    public boolean K;
    public boolean L;
    public final C1963dG M;
    public final Uri a;
    public final Fw b;
    public final C1 c;
    public final C2866yE d;
    public final C2866yE e;
    public final C2781wF f;
    public final long g;
    public final long h;
    public final Iw j;
    public final Handler n;
    public InterfaceC1962dF o;
    public O0 p;
    public C2910zF[] q;
    public C2652tF[] r;
    public boolean s;
    public boolean t;
    public boolean u;
    public boolean v;
    public com.quizlet.data.repository.user.e w;
    public InterfaceC2122h0 x;
    public long y;
    public boolean z;
    public final C2326lq i = new C2326lq(1);
    public final C1973dj k = new C1973dj();
    public final RunnableC2481pF l = new RunnableC2481pF(this, 1);
    public final RunnableC2481pF m = new RunnableC2481pF(this, 2);

    static {
        HashMap map = new HashMap();
        map.put("Icy-MetaData", "1");
        V = Collections.unmodifiableMap(map);
        EF ef = new EF();
        ef.a = "icy";
        ef.d("application/x-icy");
        W = new C1832aG(ef);
    }

    public C2695uF(Uri uri, Fw fw, Iw iw, C1 c1, C2866yE c2866yE, C2866yE c2866yE2, C2781wF c2781wF, C1963dG c1963dG, int i, long j) {
        this.a = uri;
        this.b = fw;
        this.c = c1;
        this.e = c2866yE;
        this.d = c2866yE2;
        this.f = c2781wF;
        this.M = c1963dG;
        this.g = i;
        this.j = iw;
        this.h = j;
        Looper looperMyLooper = Looper.myLooper();
        AbstractC1795We.p(looperMyLooper);
        this.n = new Handler(looperMyLooper, null);
        this.r = new C2652tF[0];
        this.q = new C2910zF[0];
        this.H = -9223372036854775807L;
        this.A = 1;
    }

    public final boolean A() {
        return this.H != -9223372036854775807L;
    }

    public final boolean B() {
        return this.C || A();
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long a() {
        return b();
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long b() {
        long jT;
        boolean z;
        long j;
        v();
        if (this.K || this.E == 0) {
            return Long.MIN_VALUE;
        }
        if (A()) {
            return this.H;
        }
        if (this.u) {
            int length = this.q.length;
            jT = Long.MAX_VALUE;
            for (int i = 0; i < length; i++) {
                com.quizlet.data.repository.user.e eVar = this.w;
                if (((boolean[]) eVar.c)[i] && ((boolean[]) eVar.d)[i]) {
                    C2910zF c2910zF = this.q[i];
                    synchronized (c2910zF) {
                        z = c2910zF.u;
                    }
                    if (z) {
                        continue;
                    } else {
                        C2910zF c2910zF2 = this.q[i];
                        synchronized (c2910zF2) {
                            j = c2910zF2.t;
                        }
                        jT = Math.min(jT, j);
                    }
                }
            }
        } else {
            jT = Long.MAX_VALUE;
        }
        if (jT == Long.MAX_VALUE) {
            jT = t(false);
        }
        return jT == Long.MIN_VALUE ? this.G : jT;
    }

    /* JADX WARN: Removed duplicated region for block: B:56:0x009d  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00b9  */
    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long c(long r13) {
        /*
            Method dump skipped, instructions count: 203
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2695uF.c(long):long");
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final void d(long j) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void e(InterfaceC1962dF interfaceC1962dF, long j) {
        this.o = interfaceC1962dF;
        this.k.c();
        z();
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x0081 A[RETURN] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long f(long r22, com.google.android.gms.internal.ads.OD r24) {
        /*
            r21 = this;
            r0 = r21
            r1 = r22
            r3 = r24
            r0.v()
            com.google.android.gms.internal.ads.h0 r4 = r0.x
            boolean r4 = r4.g()
            r5 = 0
            if (r4 != 0) goto L14
            return r5
        L14:
            com.google.android.gms.internal.ads.h0 r4 = r0.x
            com.google.android.gms.internal.ads.g0 r4 = r4.b(r1)
            com.google.android.gms.internal.ads.i0 r7 = r4.a
            long r8 = r3.a
            int r10 = (r8 > r5 ? 1 : (r8 == r5 ? 0 : -1))
            long r11 = r3.b
            if (r10 != 0) goto L2a
            int r3 = (r11 > r5 ? 1 : (r11 == r5 ? 0 : -1))
            if (r3 != 0) goto L29
            return r1
        L29:
            r8 = r5
        L2a:
            long r13 = r7.a
            java.lang.String r3 = com.google.android.gms.internal.ads.Yo.a
            long r15 = r1 - r8
            long r7 = r1 ^ r8
            long r9 = r1 ^ r15
            long r17 = r1 + r11
            long r19 = r1 ^ r17
            long r11 = r11 ^ r17
            long r7 = r7 & r9
            int r3 = (r7 > r5 ? 1 : (r7 == r5 ? 0 : -1))
            if (r3 >= 0) goto L41
            r15 = -9223372036854775808
        L41:
            long r7 = r19 & r11
            int r3 = (r7 > r5 ? 1 : (r7 == r5 ? 0 : -1))
            if (r3 >= 0) goto L4c
            r17 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
        L4c:
            int r3 = (r15 > r13 ? 1 : (r15 == r13 ? 0 : -1))
            r5 = 1
            r6 = 0
            if (r3 > 0) goto L58
            int r3 = (r13 > r17 ? 1 : (r13 == r17 ? 0 : -1))
            if (r3 > 0) goto L58
            r3 = r5
            goto L59
        L58:
            r3 = r6
        L59:
            com.google.android.gms.internal.ads.i0 r4 = r4.b
            long r7 = r4.a
            int r4 = (r15 > r7 ? 1 : (r15 == r7 ? 0 : -1))
            if (r4 > 0) goto L66
            int r4 = (r7 > r17 ? 1 : (r7 == r17 ? 0 : -1))
            if (r4 > 0) goto L66
            goto L67
        L66:
            r5 = r6
        L67:
            if (r3 == 0) goto L7c
            if (r5 == 0) goto L7c
            long r3 = r13 - r1
            long r1 = r7 - r1
            long r3 = java.lang.Math.abs(r3)
            long r1 = java.lang.Math.abs(r1)
            int r1 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r1 > 0) goto L81
            goto L7e
        L7c:
            if (r3 == 0) goto L7f
        L7e:
            return r13
        L7f:
            if (r5 == 0) goto L82
        L81:
            return r7
        L82:
            return r15
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2695uF.f(long, com.google.android.gms.internal.ads.OD):long");
    }

    public final void g(C2566rF c2566rF, boolean z) throws RemoteException, IOException {
        Uri uri = c2566rF.b.b;
        YE ye = new YE();
        androidx.compose.animation.core.S0 s0 = new androidx.compose.animation.core.S0(-1, null, Yo.w(c2566rF.i), Yo.w(this.y));
        C2866yE c2866yE = this.d;
        c2866yE.a(new C2181iF(c2866yE, ye, s0, 1));
        if (z) {
            return;
        }
        for (C2910zF c2910zF : this.q) {
            c2910zF.m(false);
        }
        if (this.E > 0) {
            InterfaceC1962dF interfaceC1962dF = this.o;
            interfaceC1962dF.getClass();
            interfaceC1962dF.g(this);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final HF h() {
        v();
        return (HF) this.w.b;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final void i() throws IOException {
        IOException iOException;
        int i = this.A == 7 ? 6 : 3;
        C2326lq c2326lq = this.i;
        IOException iOException2 = (IOException) c2326lq.d;
        if (iOException2 != null) {
            throw iOException2;
        }
        HandlerC2094gG handlerC2094gG = (HandlerC2094gG) c2326lq.c;
        if (handlerC2094gG != null && (iOException = handlerC2094gG.c) != null && handlerC2094gG.d > i) {
            throw iOException;
        }
        if (this.K && !this.t) {
            throw zzaz.a(null, "Loading finished before preparation is complete.");
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long j() {
        if (this.D) {
            this.D = false;
        } else {
            if (!this.C) {
                return -9223372036854775807L;
            }
            if (!this.K && s() <= this.J) {
                return -9223372036854775807L;
            }
            this.C = false;
        }
        return this.G;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean k(C2607sD c2607sD) {
        if (this.K) {
            return false;
        }
        C2326lq c2326lq = this.i;
        if (((IOException) c2326lq.d) != null || this.I) {
            return false;
        }
        if (this.t && this.E == 0) {
            return false;
        }
        boolean zC = this.k.c();
        if (((HandlerC2094gG) c2326lq.c) != null) {
            return zC;
        }
        z();
        return true;
    }

    public final void l(C2566rF c2566rF) throws RemoteException, IOException {
        if (this.y == -9223372036854775807L && this.x != null) {
            long jT = t(true);
            long j = jT == Long.MIN_VALUE ? 0L : jT + 10000;
            this.y = j;
            this.f.s(j, this.x, this.z);
        }
        Uri uri = c2566rF.b.b;
        YE ye = new YE();
        androidx.compose.animation.core.S0 s0 = new androidx.compose.animation.core.S0(-1, null, Yo.w(c2566rF.i), Yo.w(this.y));
        C2866yE c2866yE = this.d;
        c2866yE.a(new C2181iF(c2866yE, ye, s0, 0));
        this.K = true;
        InterfaceC1962dF interfaceC1962dF = this.o;
        interfaceC1962dF.getClass();
        interfaceC1962dF.g(this);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    public final long m(XF[] xfArr, boolean[] zArr, AF[] afArr, boolean[] zArr2, long j) {
        boolean[] zArr3;
        XF xf;
        v();
        com.quizlet.data.repository.user.e eVar = this.w;
        HF hf = (HF) eVar.b;
        int i = this.E;
        int i2 = 0;
        while (true) {
            int length = xfArr.length;
            zArr3 = (boolean[]) eVar.d;
            if (i2 >= length) {
                break;
            }
            AF af = afArr[i2];
            if (af != null && (xfArr[i2] == null || !zArr[i2])) {
                int i3 = ((C2609sF) af).a;
                AbstractC1795We.L(zArr3[i3]);
                this.E--;
                zArr3[i3] = false;
                afArr[i2] = null;
            }
            i2++;
        }
        boolean z = !this.B ? j == 0 || this.v : i != 0;
        for (int i4 = 0; i4 < xfArr.length; i4++) {
            if (afArr[i4] == null && (xf = xfArr[i4]) != null) {
                AbstractC1795We.L(xf.g() == 1);
                AbstractC1795We.L(xf.u(0) == 0);
                int iIndexOf = hf.b.indexOf(xf.a());
                if (iIndexOf < 0) {
                    iIndexOf = -1;
                }
                AbstractC1795We.L(!zArr3[iIndexOf]);
                this.E++;
                zArr3[iIndexOf] = true;
                this.D = xf.zzb().s | this.D;
                afArr[i4] = new C2609sF(this, iIndexOf);
                zArr2[i4] = true;
                if (!z) {
                    C2910zF c2910zF = this.q[iIndexOf];
                    z = (c2910zF.o + c2910zF.q == 0 || c2910zF.g(j, true)) ? false : true;
                }
            }
        }
        if (this.E == 0) {
            this.I = false;
            this.C = false;
            this.D = false;
            C2326lq c2326lq = this.i;
            if (((HandlerC2094gG) c2326lq.c) != null) {
                for (C2910zF c2910zF2 : this.q) {
                    c2910zF2.l();
                }
                HandlerC2094gG handlerC2094gG = (HandlerC2094gG) c2326lq.c;
                AbstractC1795We.p(handlerC2094gG);
                handlerC2094gG.a(false);
            } else {
                this.K = false;
                for (C2910zF c2910zF3 : this.q) {
                    c2910zF3.m(false);
                }
            }
        } else if (z) {
            j = c(j);
            for (int i5 = 0; i5 < afArr.length; i5++) {
                if (afArr[i5] != null) {
                    zArr2[i5] = true;
                }
            }
        }
        this.B = true;
        return j;
    }

    @Override // com.google.android.gms.internal.ads.W
    public final void n() {
        this.s = true;
        this.n.post(this.l);
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean o() {
        boolean z;
        if (((HandlerC2094gG) this.i.c) == null) {
            return false;
        }
        C1973dj c1973dj = this.k;
        synchronized (c1973dj) {
            z = c1973dj.a;
        }
        return z;
    }

    @Override // com.google.android.gms.internal.ads.W
    public final void p(InterfaceC2122h0 interfaceC2122h0) {
        this.n.post(new RunnableC2793wl(26, this, interfaceC2122h0));
    }

    @Override // com.google.android.gms.internal.ads.W
    public final InterfaceC2380n0 q(int i, int i2) {
        return u(new C2652tF(i, false));
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0032  */
    @Override // com.google.android.gms.internal.ads.InterfaceC2005eF
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void r(long r12) {
        /*
            r11 = this;
            boolean r0 = r11.v
            if (r0 == 0) goto L5
            goto L5d
        L5:
            r11.v()
            boolean r0 = r11.A()
            if (r0 != 0) goto L5d
            com.quizlet.data.repository.user.e r0 = r11.w
            java.lang.Object r0 = r0.d
            boolean[] r0 = (boolean[]) r0
            com.google.android.gms.internal.ads.zF[] r1 = r11.q
            int r1 = r1.length
            r2 = 0
        L18:
            if (r2 >= r1) goto L5d
            com.google.android.gms.internal.ads.zF[] r3 = r11.q
            r4 = r3[r2]
            boolean r3 = r0[r2]
            com.google.android.gms.internal.ads.xF r10 = r4.a
            monitor-enter(r4)
            int r5 = r4.n     // Catch: java.lang.Throwable -> L3e
            if (r5 == 0) goto L32
            long[] r6 = r4.l     // Catch: java.lang.Throwable -> L3e
            r7 = r5
            int r5 = r4.p     // Catch: java.lang.Throwable -> L3e
            r8 = r6[r5]     // Catch: java.lang.Throwable -> L3e
            int r6 = (r12 > r8 ? 1 : (r12 == r8 ? 0 : -1))
            if (r6 >= 0) goto L34
        L32:
            r7 = r12
            goto L51
        L34:
            if (r3 == 0) goto L41
            int r3 = r4.q     // Catch: java.lang.Throwable -> L3e
            if (r3 == r7) goto L41
            int r3 = r3 + 1
            r6 = r3
            goto L42
        L3e:
            r0 = move-exception
            r12 = r0
            goto L5b
        L41:
            r6 = r7
        L42:
            r9 = 0
            r7 = r12
            int r12 = r4.h(r5, r6, r7, r9)     // Catch: java.lang.Throwable -> L3e
            r13 = -1
            if (r12 == r13) goto L51
            long r12 = r4.j(r12)     // Catch: java.lang.Throwable -> L3e
            monitor-exit(r4)
            goto L54
        L51:
            monitor-exit(r4)
            r12 = -1
        L54:
            r10.e(r12)
            int r2 = r2 + 1
            r12 = r7
            goto L18
        L5b:
            monitor-exit(r4)     // Catch: java.lang.Throwable -> L3e
            throw r12
        L5d:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2695uF.r(long):void");
    }

    public final int s() {
        int i = 0;
        for (C2910zF c2910zF : this.q) {
            i += c2910zF.o + c2910zF.n;
        }
        return i;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0017  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long t(boolean r7) {
        /*
            r6 = this;
            r0 = 0
            r1 = -9223372036854775808
        L3:
            com.google.android.gms.internal.ads.zF[] r3 = r6.q
            int r4 = r3.length
            if (r0 >= r4) goto L27
            if (r7 != 0) goto L17
            com.quizlet.data.repository.user.e r4 = r6.w
            r4.getClass()
            java.lang.Object r4 = r4.d
            boolean[] r4 = (boolean[]) r4
            boolean r4 = r4[r0]
            if (r4 == 0) goto L21
        L17:
            r3 = r3[r0]
            monitor-enter(r3)
            long r4 = r3.t     // Catch: java.lang.Throwable -> L24
            monitor-exit(r3)
            long r1 = java.lang.Math.max(r1, r4)
        L21:
            int r0 = r0 + 1
            goto L3
        L24:
            r7 = move-exception
            monitor-exit(r3)     // Catch: java.lang.Throwable -> L24
            throw r7
        L27:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2695uF.t(boolean):long");
    }

    public final InterfaceC2380n0 u(C2652tF c2652tF) {
        int length = this.q.length;
        for (int i = 0; i < length; i++) {
            if (c2652tF.equals(this.r[i])) {
                return this.q[i];
            }
        }
        if (this.s) {
            AbstractC2096gb.J("ProgressiveMediaPeriod", "Extractor added new track (id=" + c2652tF.a + ") after finishing tracks.");
            return new T();
        }
        C2910zF c2910zF = new C2910zF(this.M, this.c, this.e);
        c2910zF.e = this;
        int i2 = length + 1;
        C2652tF[] c2652tFArr = (C2652tF[]) Arrays.copyOf(this.r, i2);
        c2652tFArr[length] = c2652tF;
        String str = Yo.a;
        this.r = c2652tFArr;
        C2910zF[] c2910zFArr = (C2910zF[]) Arrays.copyOf(this.q, i2);
        c2910zFArr[length] = c2910zF;
        this.q = c2910zFArr;
        return c2910zF;
    }

    public final void v() {
        AbstractC1795We.L(this.t);
        this.w.getClass();
        this.x.getClass();
    }

    public final void w() {
        long j;
        C1832aG c1832aG;
        K4 k4A;
        int i;
        C1832aG c1832aG2;
        boolean z = false;
        if (this.L || this.t || !this.s || this.x == null) {
            return;
        }
        C2910zF[] c2910zFArr = this.q;
        int length = c2910zFArr.length;
        int i2 = 0;
        while (true) {
            if (i2 >= length) {
                C1973dj c1973dj = this.k;
                synchronized (c1973dj) {
                    c1973dj.a = false;
                }
                int length2 = this.q.length;
                J9[] j9Arr = new J9[length2];
                boolean[] zArr = new boolean[length2];
                int i3 = 0;
                while (true) {
                    j = this.h;
                    if (i3 >= length2) {
                        break;
                    }
                    C2910zF c2910zF = this.q[i3];
                    synchronized (c2910zF) {
                        c1832aG = c2910zF.w ? null : c2910zF.x;
                    }
                    c1832aG.getClass();
                    String str = c1832aG.m;
                    boolean zH = AbstractC2514q5.h(str);
                    boolean z2 = (zH || AbstractC2514q5.j(str)) ? true : z;
                    zArr[i3] = z2;
                    boolean z3 = z;
                    this.u |= z2;
                    this.v = (j != -9223372036854775807L && length2 == 1 && AbstractC2514q5.i(str)) ? true : z3 ? 1 : 0;
                    O0 o0 = this.p;
                    if (o0 != null) {
                        if (zH || this.r[i3].b) {
                            K4 k4 = c1832aG.k;
                            if (k4 == null) {
                                InterfaceC2856y4[] interfaceC2856y4Arr = new InterfaceC2856y4[1];
                                interfaceC2856y4Arr[z3 ? 1 : 0] = o0;
                                k4A = new K4(interfaceC2856y4Arr);
                            } else {
                                InterfaceC2856y4[] interfaceC2856y4Arr2 = new InterfaceC2856y4[1];
                                interfaceC2856y4Arr2[z3 ? 1 : 0] = o0;
                                k4A = k4.a(interfaceC2856y4Arr2);
                            }
                            EF ef = new EF(c1832aG);
                            ef.j = k4A;
                            c1832aG = new C1832aG(ef);
                        }
                        if (zH && c1832aG.g == -1 && c1832aG.h == -1 && (i = o0.a) != -1) {
                            EF ef2 = new EF(c1832aG);
                            ef2.g = i;
                            c1832aG = new C1832aG(ef2);
                        }
                    }
                    this.c.getClass();
                    int i4 = c1832aG.q != null ? 1 : z3 ? 1 : 0;
                    EF ef3 = new EF(c1832aG);
                    ef3.I = i4;
                    C1832aG c1832aG3 = new C1832aG(ef3);
                    j9Arr[i3] = new J9(Integer.toString(i3), c1832aG3);
                    this.D = c1832aG3.s | this.D;
                    i3++;
                    z = z3 ? 1 : 0;
                }
                this.w = new com.quizlet.data.repository.user.e(new HF(j9Arr), zArr);
                if (this.v && this.y == -9223372036854775807L) {
                    this.y = j;
                    this.x = new C2524qF(this, this.x);
                }
                this.f.s(this.y, this.x, this.z);
                this.t = true;
                InterfaceC1962dF interfaceC1962dF = this.o;
                interfaceC1962dF.getClass();
                interfaceC1962dF.l(this);
                return;
            }
            C2910zF c2910zF2 = c2910zFArr[i2];
            synchronized (c2910zF2) {
                c1832aG2 = c2910zF2.w ? null : c2910zF2.x;
            }
            if (c1832aG2 == null) {
                return;
            } else {
                i2++;
            }
        }
    }

    public final void x(int i) throws RemoteException, IOException {
        v();
        com.quizlet.data.repository.user.e eVar = this.w;
        boolean[] zArr = (boolean[]) eVar.e;
        if (zArr[i]) {
            return;
        }
        C1832aG c1832aG = ((HF) eVar.b).a(i).d[0];
        androidx.compose.animation.core.S0 s0 = new androidx.compose.animation.core.S0(AbstractC2514q5.b(c1832aG.m), c1832aG, Yo.w(this.G), -9223372036854775807L);
        C2866yE c2866yE = this.d;
        c2866yE.a(new Fp(c2866yE, false, s0, 13));
        zArr[i] = true;
    }

    public final void y(int i) {
        v();
        if (this.I) {
            if ((!this.u || ((boolean[]) this.w.c)[i]) && !this.q[i].n(false)) {
                this.H = 0L;
                this.I = false;
                this.C = true;
                this.G = 0L;
                this.J = 0;
                for (C2910zF c2910zF : this.q) {
                    c2910zF.m(false);
                }
                InterfaceC1962dF interfaceC1962dF = this.o;
                interfaceC1962dF.getClass();
                interfaceC1962dF.g(this);
            }
        }
    }

    public final void z() {
        C2566rF c2566rF = new C2566rF(this, this.a, this.b, this.j, this, this.k);
        if (this.t) {
            AbstractC1795We.L(A());
            long j = this.y;
            if (j != -9223372036854775807L && this.H > j) {
                this.K = true;
                this.H = -9223372036854775807L;
                return;
            }
            InterfaceC2122h0 interfaceC2122h0 = this.x;
            interfaceC2122h0.getClass();
            C2166i0 c2166i0 = interfaceC2122h0.b(this.H).a;
            long j2 = this.H;
            c2566rF.f.a = c2166i0.b;
            c2566rF.i = j2;
            c2566rF.h = true;
            c2566rF.l = false;
            for (C2910zF c2910zF : this.q) {
                c2910zF.r = this.H;
            }
            this.H = -9223372036854775807L;
        }
        this.J = s();
        C2326lq c2326lq = this.i;
        c2326lq.getClass();
        Looper looperMyLooper = Looper.myLooper();
        AbstractC1795We.p(looperMyLooper);
        c2326lq.d = null;
        HandlerC2094gG handlerC2094gG = new HandlerC2094gG(c2326lq, looperMyLooper, c2566rF, this, SystemClock.elapsedRealtime());
        AbstractC1795We.L(((HandlerC2094gG) c2326lq.c) == null);
        c2326lq.c = handlerC2094gG;
        handlerC2094gG.b();
    }
}
