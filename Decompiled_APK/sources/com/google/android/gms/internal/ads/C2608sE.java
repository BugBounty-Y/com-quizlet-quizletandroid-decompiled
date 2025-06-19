package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.IntentFilter;
import android.media.AudioAttributes;
import android.media.AudioFormat;
import android.media.AudioTrack;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import androidx.appcompat.view.menu.RunnableC0069f;
import androidx.camera.camera2.internal.C0148z;
import androidx.recyclerview.widget.C1395x;
import com.facebook.internal.C1549d;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.skydoves.balloon.internals.DefinitionKt;
import java.math.RoundingMode;
import java.nio.ByteBuffer;
import java.util.ArrayDeque;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.sE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2608sE {
    public static final Object Z = new Object();
    public static ScheduledExecutorService a0;
    public static int b0;
    public long A;
    public long B;
    public int C;
    public boolean D;
    public boolean E;
    public long F;
    public float G;
    public ByteBuffer H;
    public int I;
    public ByteBuffer J;
    public boolean K;
    public boolean L;
    public boolean M;
    public boolean N;
    public int O;
    public Lp P;
    public C2883yp Q;
    public long R;
    public boolean S;
    public Looper T;
    public long U;
    public long V;
    public Handler W;
    public final Iw X;
    public final C2351mE Y;
    public final Context a;
    public final C2308lE b;
    public final C2780wE c;
    public final Bu d;
    public final Bu e;
    public final C2265kE f;
    public final ArrayDeque g;
    public Iw h;
    public final C0148z i;
    public final C0148z j;
    public C1917cE k;
    public Sq l;
    public C2437oE m;
    public C2437oE n;
    public C2100gf o;
    public AudioTrack p;
    public C2004eE q;
    public Tm r;
    public Iw s;
    public Wl t;
    public C2480pE u;
    public C2480pE v;
    public C2040f6 w;
    public boolean x;
    public long y;
    public long z;

    public C2608sE(C2394nE c2394nE) {
        Context context = c2394nE.a;
        Context applicationContext = context == null ? null : context.getApplicationContext();
        this.a = applicationContext;
        this.t = Wl.b;
        this.q = applicationContext == null ? c2394nE.b : null;
        this.X = c2394nE.d;
        C2351mE c2351mE = c2394nE.e;
        c2351mE.getClass();
        this.Y = c2351mE;
        this.f = new C2265kE(new Lr(this, 11));
        C2308lE c2308lE = new C2308lE();
        this.b = c2308lE;
        C2780wE c2780wE = new C2780wE();
        c2780wE.m = Yo.b;
        this.c = c2780wE;
        C2445og c2445og = new C2445og();
        C2244ju c2244ju = AbstractC2330lu.b;
        Object[] objArr = {c2445og, c2308lE, c2780wE};
        AbstractC2457os.q(3, objArr);
        this.d = AbstractC2330lu.m(3, objArr);
        Object[] objArr2 = {new C2737vE(), c2308lE, c2780wE};
        AbstractC2457os.q(3, objArr2);
        this.e = AbstractC2330lu.m(3, objArr2);
        this.G = 1.0f;
        this.O = 0;
        this.P = new Lp();
        C2040f6 c2040f6 = C2040f6.d;
        this.v = new C2480pE(c2040f6, 0L, 0L);
        this.w = c2040f6;
        this.x = false;
        this.g = new ArrayDeque();
        this.i = new C0148z();
        this.j = new C0148z();
    }

    public static boolean m(AudioTrack audioTrack) {
        return Build.VERSION.SDK_INT >= 29 && audioTrack.isOffloadedPlayback();
    }

    public static final AudioTrack n(C1395x c1395x, Wl wl, int i, C1832aG c1832aG) throws UnsupportedOperationException, IllegalArgumentException, zzqe {
        C1832aG c1832aG2;
        RuntimeException runtimeException;
        int i2;
        int i3;
        int i4;
        try {
            i2 = c1395x.b;
            i3 = c1395x.c;
            i4 = c1395x.a;
        } catch (IllegalArgumentException e) {
            e = e;
        } catch (UnsupportedOperationException e2) {
            e = e2;
        }
        try {
            String str = Yo.a;
            AudioTrack.Builder sessionId = new AudioTrack.Builder().setAudioAttributes((AudioAttributes) wl.a().b).setAudioFormat(new AudioFormat.Builder().setSampleRate(i2).setChannelMask(i3).setEncoding(i4).build()).setTransferMode(1).setBufferSizeInBytes(c1395x.e).setSessionId(i);
            if (Build.VERSION.SDK_INT >= 29) {
                try {
                    sessionId.setOffloadedPlayback(c1395x.d);
                } catch (IllegalArgumentException | UnsupportedOperationException e3) {
                    runtimeException = e3;
                    c1832aG2 = c1832aG;
                    C1832aG c1832aG3 = c1832aG2;
                    throw new zzqe(0, c1395x.b, c1395x.c, c1395x.a, c1395x.e, c1832aG3, c1395x.d, runtimeException);
                }
            }
            AudioTrack audioTrackBuild = sessionId.build();
            int state = audioTrackBuild.getState();
            if (state == 1) {
                return audioTrackBuild;
            }
            try {
                audioTrackBuild.release();
            } catch (Exception unused) {
            }
            throw new zzqe(state, c1395x.b, c1395x.c, c1395x.a, c1395x.e, c1832aG, c1395x.d, null);
        } catch (IllegalArgumentException e4) {
            e = e4;
            c1832aG2 = c1832aG;
            runtimeException = e;
            C1832aG c1832aG32 = c1832aG2;
            throw new zzqe(0, c1395x.b, c1395x.c, c1395x.a, c1395x.e, c1832aG32, c1395x.d, runtimeException);
        } catch (UnsupportedOperationException e5) {
            e = e5;
            c1832aG2 = c1832aG;
            runtimeException = e;
            C1832aG c1832aG322 = c1832aG2;
            throw new zzqe(0, c1395x.b, c1395x.c, c1395x.a, c1395x.e, c1832aG322, c1395x.d, runtimeException);
        }
    }

    public final long a() {
        return this.n.c == 0 ? this.y / r0.b : this.z;
    }

    public final long b() {
        C2437oE c2437oE = this.n;
        if (c2437oE.c != 0) {
            return this.B;
        }
        long j = this.A;
        long j2 = c2437oE.d;
        String str = Yo.a;
        return ((j + j2) - 1) / j2;
    }

    public final AudioTrack c(C2437oE c2437oE) throws zzqe {
        try {
            return n(c2437oE.a(), this.t, this.O, c2437oE.a);
        } catch (zzqe e) {
            Sq sq = this.l;
            if (sq != null) {
                sq.c(e);
            }
            throw e;
        }
    }

    public final void d(long j) {
        boolean z;
        C2040f6 c2040f6;
        C2437oE c2437oE = this.n;
        boolean z2 = false;
        if (c2437oE.c == 0) {
            int i = c2437oE.a.E;
            z = true;
        } else {
            z = false;
        }
        Iw iw = this.X;
        if (z) {
            c2040f6 = this.w;
            iw.getClass();
            float f = c2040f6.a;
            C1926cg c1926cg = (C1926cg) iw.b;
            c1926cg.getClass();
            AbstractC1795We.B(f > DefinitionKt.NO_Float_VALUE);
            if (c1926cg.c != f) {
                c1926cg.c = f;
                c1926cg.i = true;
            }
            float f2 = c2040f6.b;
            AbstractC1795We.B(f2 > DefinitionKt.NO_Float_VALUE);
            if (c1926cg.d != f2) {
                c1926cg.d = f2;
                c1926cg.i = true;
            }
        } else {
            c2040f6 = C2040f6.d;
        }
        C2040f6 c2040f62 = c2040f6;
        this.w = c2040f62;
        C2437oE c2437oE2 = this.n;
        if (c2437oE2.c == 0) {
            int i2 = c2437oE2.a.E;
            z2 = this.x;
            ((C2694uE) iw.a).j = z2;
        }
        this.x = z2;
        this.g.add(new C2480pE(c2040f62, Math.max(0L, j), Yo.u(this.n.e, b())));
        C2100gf c2100gf = this.n.i;
        this.o = c2100gf;
        c2100gf.b();
        Sq sq = this.l;
        if (sq != null) {
            boolean z3 = this.x;
            Fp fp = ((C2651tE) sq.a).F1;
            Handler handler = (Handler) fp.b;
            if (handler != null) {
                handler.post(new com.bumptech.glide.manager.o(z3, 6, fp));
            }
        }
    }

    public final void e() throws zzqh {
        boolean z;
        if (this.J == null) {
            return;
        }
        C0148z c0148z = this.j;
        if (((Exception) c0148z.d) != null) {
            synchronized (Z) {
                z = b0 > 0;
            }
            if (z || SystemClock.elapsedRealtime() < c0148z.c) {
                return;
            }
        }
        int iRemaining = this.J.remaining();
        int iWrite = this.p.write(this.J, iRemaining, 1);
        this.R = SystemClock.elapsedRealtime();
        if (iWrite >= 0) {
            c0148z.d = null;
            c0148z.b = -9223372036854775807L;
            c0148z.c = -9223372036854775807L;
            m(this.p);
            int i = this.n.c;
            if (i == 0) {
                this.A += iWrite;
            }
            if (iWrite == iRemaining) {
                if (i != 0) {
                    AbstractC1795We.L(this.J == this.H);
                    this.B = (this.C * this.I) + this.B;
                }
                this.J = null;
                return;
            }
            return;
        }
        if (iWrite == -6 || iWrite == -32) {
            if (b() > 0) {
                z = true;
            } else if (m(this.p)) {
                if (this.n.c == 1) {
                    this.S = true;
                }
                z = true;
            }
        }
        zzqh zzqhVar = new zzqh(iWrite, this.n.a, z);
        Sq sq = this.l;
        if (sq != null) {
            sq.c(zzqhVar);
        }
        if (!zzqhVar.b || this.a == null) {
            c0148z.h(zzqhVar);
        } else {
            this.q = C2004eE.c;
            throw zzqhVar;
        }
    }

    public final void f() {
        Context context;
        C2004eE c2004eEC;
        if (this.r == null && (context = this.a) != null) {
            this.T = Looper.myLooper();
            Tm tm = new Tm(context, new C2586rt(this, 8), this.t, this.Q);
            this.r = tm;
            if (tm.a) {
                c2004eEC = (C2004eE) tm.g;
                c2004eEC.getClass();
            } else {
                tm.a = true;
                C2092gE c2092gE = (C2092gE) tm.f;
                if (c2092gE != null) {
                    c2092gE.a.registerContentObserver(c2092gE.b, false, c2092gE);
                }
                Handler handler = (Handler) tm.c;
                Context context2 = (Context) tm.b;
                C2048fE c2048fE = (C2048fE) tm.d;
                if (c2048fE != null) {
                    AbstractC1795We.s(context2).registerAudioDeviceCallback(c2048fE, handler);
                }
                c2004eEC = C2004eE.c(context2, context2.registerReceiver((C1549d) tm.e, new IntentFilter("android.media.action.HDMI_AUDIO_PLUG"), null, handler), (Wl) tm.i, (C2883yp) tm.h);
                tm.g = c2004eEC;
            }
            this.q = c2004eEC;
        }
        this.q.getClass();
    }

    public final void g() throws IllegalStateException {
        if (this.L) {
            return;
        }
        this.L = true;
        long jB = b();
        C2265kE c2265kE = this.f;
        c2265kE.x = c2265kE.c();
        c2265kE.E.getClass();
        c2265kE.v = Yo.t(SystemClock.elapsedRealtime());
        c2265kE.y = jB;
        if (m(this.p)) {
            this.M = false;
        }
        this.p.stop();
    }

    public final void h() throws zzqh {
        ByteBuffer byteBuffer;
        e();
        if (this.J != null) {
            return;
        }
        if (!this.o.d()) {
            ByteBuffer byteBuffer2 = this.H;
            if (byteBuffer2 != null) {
                i(byteBuffer2);
                e();
                return;
            }
            return;
        }
        while (!this.o.c()) {
            do {
                C2100gf c2100gf = this.o;
                if (c2100gf.d()) {
                    ByteBuffer byteBuffer3 = c2100gf.c[c2100gf.e()];
                    if (byteBuffer3.hasRemaining()) {
                        byteBuffer = byteBuffer3;
                    } else {
                        c2100gf.f(InterfaceC1688Ef.a);
                        byteBuffer = c2100gf.c[c2100gf.e()];
                    }
                } else {
                    byteBuffer = InterfaceC1688Ef.a;
                }
                if (byteBuffer.hasRemaining()) {
                    i(byteBuffer);
                    e();
                } else {
                    ByteBuffer byteBuffer4 = this.H;
                    if (byteBuffer4 == null || !byteBuffer4.hasRemaining()) {
                        return;
                    }
                    C2100gf c2100gf2 = this.o;
                    ByteBuffer byteBuffer5 = this.H;
                    if (c2100gf2.d() && !c2100gf2.d) {
                        c2100gf2.f(byteBuffer5);
                    }
                }
            } while (this.J == null);
            return;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:45:0x0145  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x01dd  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0204  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x01f2 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:82:0x004f A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i(java.nio.ByteBuffer r19) {
        /*
            Method dump skipped, instructions count: 521
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2608sE.i(java.nio.ByteBuffer):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:20:0x0042 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0043 A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean j() throws com.google.android.gms.internal.ads.zzqh {
        /*
            r4 = this;
            com.google.android.gms.internal.ads.gf r0 = r4.o
            boolean r0 = r0.d()
            r1 = 0
            r2 = 1
            if (r0 != 0) goto L12
            r4.e()
            java.nio.ByteBuffer r0 = r4.J
            if (r0 != 0) goto L43
            goto L42
        L12:
            com.google.android.gms.internal.ads.gf r0 = r4.o
            boolean r3 = r0.d()
            if (r3 == 0) goto L2c
            boolean r3 = r0.d
            if (r3 == 0) goto L1f
            goto L2c
        L1f:
            r0.d = r2
            java.util.ArrayList r0 = r0.b
            java.lang.Object r0 = r0.get(r1)
            com.google.android.gms.internal.ads.Ef r0 = (com.google.android.gms.internal.ads.InterfaceC1688Ef) r0
            r0.j()
        L2c:
            r4.h()
            com.google.android.gms.internal.ads.gf r0 = r4.o
            boolean r0 = r0.c()
            if (r0 == 0) goto L43
            java.nio.ByteBuffer r0 = r4.J
            if (r0 == 0) goto L42
            boolean r0 = r0.hasRemaining()
            if (r0 == 0) goto L42
            goto L43
        L42:
            return r2
        L43:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2608sE.j():boolean");
    }

    public final boolean k() {
        return this.p != null;
    }

    public final int l(C1832aG c1832aG) {
        f();
        if (!"audio/raw".equals(c1832aG.m)) {
            return this.q.a(c1832aG, this.t) != null ? 2 : 0;
        }
        int i = c1832aG.E;
        if (Yo.c(i)) {
            return i != 2 ? 1 : 2;
        }
        AbstractC1642h.s(i, "Invalid PCM encoding: ", "DefaultAudioSink");
        return 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x00fd  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0106  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void o(com.google.android.gms.internal.ads.C1832aG r23, int[] r24) throws com.google.android.gms.internal.ads.zzqd {
        /*
            Method dump skipped, instructions count: 473
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2608sE.o(com.google.android.gms.internal.ads.aG, int[]):void");
    }

    public final void p() throws IllegalStateException {
        if (k()) {
            this.y = 0L;
            this.z = 0L;
            this.A = 0L;
            this.B = 0L;
            this.C = 0;
            this.v = new C2480pE(this.w, 0L, 0L);
            this.F = 0L;
            this.u = null;
            this.g.clear();
            this.H = null;
            this.I = 0;
            this.J = null;
            this.L = false;
            this.K = false;
            this.M = false;
            this.c.o = 0L;
            C2100gf c2100gf = this.n.i;
            this.o = c2100gf;
            c2100gf.b();
            C2265kE c2265kE = this.f;
            AudioTrack audioTrack = c2265kE.c;
            audioTrack.getClass();
            if (audioTrack.getPlayState() == 3) {
                this.p.pause();
            }
            if (m(this.p)) {
                Iw iw = this.h;
                iw.getClass();
                this.p.unregisterStreamEventCallback((C2565rE) iw.a);
                ((Handler) iw.c).removeCallbacksAndMessages(null);
            }
            C1395x c1395xA = this.n.a();
            C2437oE c2437oE = this.m;
            if (c2437oE != null) {
                this.n = c2437oE;
                this.m = null;
            }
            c2265kE.j = 0L;
            c2265kE.u = 0;
            c2265kE.t = 0;
            c2265kE.k = 0L;
            c2265kE.A = 0L;
            c2265kE.D = 0L;
            c2265kE.i = false;
            c2265kE.c = null;
            c2265kE.e = null;
            Iw iw2 = this.s;
            if (iw2 != null) {
                C2523qE c2523qE = (C2523qE) iw2.b;
                c2523qE.getClass();
                ((AudioTrack) iw2.c).removeOnRoutingChangedListener(c2523qE);
                iw2.b = null;
                this.s = null;
            }
            AudioTrack audioTrack2 = this.p;
            Sq sq = this.l;
            Handler handler = new Handler(Looper.myLooper());
            synchronized (Z) {
                try {
                    if (a0 == null) {
                        String str = Yo.a;
                        a0 = Executors.newSingleThreadScheduledExecutor(new Po());
                    }
                    b0++;
                    a0.schedule(new RunnableC0069f(11, audioTrack2, sq, handler, c1395xA, false), 20L, TimeUnit.MILLISECONDS);
                } catch (Throwable th) {
                    throw th;
                }
            }
            this.p = null;
        }
        C0148z c0148z = this.j;
        c0148z.d = null;
        c0148z.b = -9223372036854775807L;
        c0148z.c = -9223372036854775807L;
        C0148z c0148z2 = this.i;
        c0148z2.d = null;
        c0148z2.b = -9223372036854775807L;
        c0148z2.c = -9223372036854775807L;
        this.U = 0L;
        this.V = 0L;
        Handler handler2 = this.W;
        if (handler2 != null) {
            handler2.removeCallbacksAndMessages(null);
        }
    }

    public final void q() throws IllegalStateException {
        this.N = true;
        if (k()) {
            C2265kE c2265kE = this.f;
            if (c2265kE.v != -9223372036854775807L) {
                c2265kE.E.getClass();
                c2265kE.v = Yo.t(SystemClock.elapsedRealtime());
            }
            C2222jE c2222jE = c2265kE.e;
            c2222jE.getClass();
            c2222jE.a(0);
            this.p.play();
        }
    }

    public final void r() throws IllegalStateException {
        p();
        Bu bu = this.d;
        int i = bu.d;
        for (int i2 = 0; i2 < i; i2++) {
            ((InterfaceC1688Ef) bu.get(i2)).f();
        }
        Bu bu2 = this.e;
        int i3 = bu2.d;
        for (int i4 = 0; i4 < i3; i4++) {
            ((InterfaceC1688Ef) bu2.get(i4)).f();
        }
        C2100gf c2100gf = this.o;
        if (c2100gf != null) {
            int i5 = 0;
            while (true) {
                Bu bu3 = c2100gf.a;
                if (i5 >= bu3.d) {
                    break;
                }
                InterfaceC1688Ef interfaceC1688Ef = (InterfaceC1688Ef) bu3.get(i5);
                interfaceC1688Ef.a();
                interfaceC1688Ef.f();
                i5++;
            }
            c2100gf.c = new ByteBuffer[0];
            C2229jf c2229jf = C2229jf.e;
            c2100gf.d = false;
        }
        this.N = false;
        this.S = false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:247:0x04ce, code lost:
    
        if (r6 != 0) goto L251;
     */
    /* JADX WARN: Removed duplicated region for block: B:150:0x02c4  */
    /* JADX WARN: Removed duplicated region for block: B:153:0x02e3  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x039e  */
    /* JADX WARN: Removed duplicated region for block: B:199:0x03a3  */
    /* JADX WARN: Removed duplicated region for block: B:201:0x03a9  */
    /* JADX WARN: Removed duplicated region for block: B:298:0x05bb A[Catch: zzqe -> 0x0115, TryCatch #2 {zzqe -> 0x0115, blocks: (B:35:0x0077, B:66:0x00eb, B:68:0x00f3, B:70:0x00f9, B:73:0x0118, B:74:0x0132, B:76:0x0138, B:78:0x013c, B:79:0x013e, B:83:0x0147, B:84:0x0148, B:86:0x0151, B:91:0x0158, B:92:0x0159, B:94:0x0178, B:95:0x017f, B:97:0x0188, B:99:0x0195, B:100:0x019e, B:102:0x01a2, B:103:0x01c6, B:105:0x01cc, B:107:0x01de, B:60:0x00ad, B:62:0x00b6, B:295:0x05b2, B:296:0x05b5, B:298:0x05bb, B:299:0x05bd, B:38:0x007e, B:39:0x0080, B:47:0x008c, B:302:0x05c0, B:64:0x00e4, B:80:0x013f, B:82:0x0143, B:88:0x0155, B:54:0x009c, B:56:0x00a0, B:59:0x00ac, B:40:0x0081, B:44:0x0088), top: B:311:0x0077, inners: #0, #1, #3, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:312:0x009c A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:319:? A[Catch: zzqe -> 0x0115, SYNTHETIC, TRY_LEAVE, TryCatch #2 {zzqe -> 0x0115, blocks: (B:35:0x0077, B:66:0x00eb, B:68:0x00f3, B:70:0x00f9, B:73:0x0118, B:74:0x0132, B:76:0x0138, B:78:0x013c, B:79:0x013e, B:83:0x0147, B:84:0x0148, B:86:0x0151, B:91:0x0158, B:92:0x0159, B:94:0x0178, B:95:0x017f, B:97:0x0188, B:99:0x0195, B:100:0x019e, B:102:0x01a2, B:103:0x01c6, B:105:0x01cc, B:107:0x01de, B:60:0x00ad, B:62:0x00b6, B:295:0x05b2, B:296:0x05b5, B:298:0x05bb, B:299:0x05bd, B:38:0x007e, B:39:0x0080, B:47:0x008c, B:302:0x05c0, B:64:0x00e4, B:80:0x013f, B:82:0x0143, B:88:0x0155, B:54:0x009c, B:56:0x00a0, B:59:0x00ac, B:40:0x0081, B:44:0x0088), top: B:311:0x0077, inners: #0, #1, #3, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:324:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean s(java.nio.ByteBuffer r31, long r32, int r34) throws java.lang.IllegalStateException, com.google.android.gms.internal.ads.zzqh, com.google.android.gms.internal.ads.zzqe {
        /*
            Method dump skipped, instructions count: 1518
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2608sE.s(java.nio.ByteBuffer, long, int):boolean");
    }

    public final boolean t() {
        if (!k()) {
            return false;
        }
        if (Build.VERSION.SDK_INT >= 29 && this.p.isOffloadedPlayback() && this.M) {
            return false;
        }
        long jB = b();
        C2265kE c2265kE = this.f;
        long jA = c2265kE.a();
        int i = c2265kE.f;
        String str = Yo.a;
        return jB > Yo.v(jA, (long) i, 1000000L, RoundingMode.UP);
    }
}
