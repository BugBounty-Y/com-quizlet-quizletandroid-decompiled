package com.google.android.gms.internal.ads;

import android.net.Uri;
import java.io.IOException;
import java.nio.ByteBuffer;

/* renamed from: com.google.android.gms.internal.ads.ae, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1837ae extends AbstractC1794Wd implements InterfaceC2828xd {
    public C2143he d;
    public String e;
    public boolean f;
    public boolean g;
    public C1746Od h;
    public long i;
    public long j;

    public static final String u(String str) {
        return "cache:".concat(String.valueOf(com.google.android.gms.ads.internal.util.client.c.a(str, "MD5")));
    }

    public static String v(String str, Exception exc) {
        return str + "/" + exc.getClass().getCanonicalName() + ":" + exc.getMessage();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void a(int i) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void d() {
        com.google.android.gms.ads.internal.util.client.i.h("Precache onRenderedFirstFrame");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void e(long j, boolean z) {
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.c.get();
        if (interfaceC2529qe != null) {
            AbstractC2270kd.f.execute(new RunnableC1698Gd(interfaceC2529qe, z, j, 1));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void g(IOException iOException) {
        com.google.android.gms.ads.internal.util.client.i.i("Precache exception", iOException);
        com.google.android.gms.ads.internal.j.C.h.g("VideoStreamExoPlayerCache.onException", iOException);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void h(String str, Exception exc) {
        com.google.android.gms.ads.internal.util.client.i.i("Precache error", exc);
        com.google.android.gms.ads.internal.j.C.h.g("VideoStreamExoPlayerCache.onError", exc);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2828xd
    public final void i(int i, int i2) {
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final void j() {
        C2143he c2143he = this.d;
        if (c2143he != null) {
            c2143he.j = null;
            PD pd = c2143he.g;
            if (pd != null) {
                pd.d.a();
                pd.c.l1(c2143he);
                PD pd2 = c2143he.g;
                pd2.d.a();
                pd2.c.k1();
                c2143he.g = null;
                C2143he.v.decrementAndGet();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final void l() {
        synchronized (this) {
            this.f = true;
            notify();
            j();
        }
        String str = this.e;
        if (str != null) {
            m(this.e, u(str), "externalAbort", "Programmatic precache abort.");
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final void n(int i) {
        C1968de c1968de = this.d.b;
        synchronized (c1968de) {
            c1968de.d = i * 1000;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final void o(int i) {
        C1968de c1968de = this.d.b;
        synchronized (c1968de) {
            c1968de.e = i * 1000;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final void p(int i) {
        C1968de c1968de = this.d.b;
        synchronized (c1968de) {
            c1968de.c = i * 1000;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final void q(int i) {
        C1968de c1968de = this.d.b;
        synchronized (c1968de) {
            c1968de.b = i * 1000;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final boolean r(String str) {
        return s(str, new String[]{str});
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v11, types: [android.os.Handler] */
    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final boolean s(String str, String[] strArr) throws Throwable {
        boolean z;
        long j;
        long j2;
        long j3;
        C1837ae c1837ae;
        long j4;
        long j5;
        long j6;
        long j7;
        boolean z2;
        long j8;
        C1837ae c1837ae2 = this;
        String str2 = str;
        c1837ae2.e = str2;
        String strU = u(str2);
        boolean z3 = false;
        try {
            Uri[] uriArr = new Uri[strArr.length];
            for (int i = 0; i < strArr.length; i++) {
                uriArr[i] = Uri.parse(strArr[i]);
            }
            C2143he c2143he = c1837ae2.d;
            c2143he.getClass();
            c2143he.q(uriArr, ByteBuffer.allocate(0), false);
            InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) c1837ae2.c.get();
            if (interfaceC2529qe != null) {
                interfaceC2529qe.P(strU, c1837ae2);
            }
            com.google.android.gms.ads.internal.j.C.k.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            C2601s7 c2601s7 = AbstractC2773w7.F;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            long jLongValue = ((Long) rVar.c.a(c2601s7)).longValue();
            long jLongValue2 = ((Long) rVar.c.a(AbstractC2773w7.E)).longValue() * 1000;
            long jIntValue = ((Integer) rVar.c.a(AbstractC2773w7.t)).intValue();
            boolean zBooleanValue = ((Boolean) rVar.c.a(AbstractC2773w7.T1)).booleanValue();
            long j9 = -1;
            c1837ae2 = c1837ae2;
            while (true) {
                synchronized (this) {
                    try {
                        if (System.currentTimeMillis() - jCurrentTimeMillis > jLongValue2) {
                            throw new IOException("Timeout reached. Limit: " + jLongValue2 + " ms");
                        }
                        if (c1837ae2.f) {
                            throw new IOException("Abort requested before buffering finished. ");
                        }
                        if (c1837ae2.g) {
                            return true;
                        }
                        PD pd = c1837ae2.d.g;
                        if (!(pd != null ? true : z3)) {
                            throw new IOException("ExoPlayer was released during preloading.");
                        }
                        long jO1 = pd.o1();
                        if (jO1 > 0) {
                            long jM1 = c1837ae2.d.g.m1();
                            if (jM1 != j9) {
                                if (jM1 > 0) {
                                    j7 = jLongValue;
                                    j6 = jO1;
                                    z2 = true;
                                } else {
                                    j7 = jLongValue;
                                    j6 = jO1;
                                    z2 = z3;
                                }
                                if (zBooleanValue) {
                                    try {
                                        C2143he c2143he2 = c1837ae2.d;
                                        j8 = (c2143he2.s == null || !c2143he2.s.o) ? c2143he2.k : 0L;
                                    } catch (Throwable th) {
                                        th = th;
                                        z = false;
                                        c1837ae2 = c1837ae2;
                                    }
                                } else {
                                    j8 = -1;
                                }
                                long jU = zBooleanValue ? c1837ae2.d.u() : -1L;
                                long jP = zBooleanValue ? c1837ae2.d.p() : -1L;
                                try {
                                    int i2 = C2143he.u.get();
                                    int i3 = C2143he.v.get();
                                    Ls ls = com.google.android.gms.ads.internal.util.client.c.b;
                                    j = jLongValue2;
                                    j5 = j7;
                                    long j10 = j8;
                                    j4 = jM1;
                                    z = false;
                                    j2 = jIntValue;
                                    try {
                                        RunnableC1764Rd runnableC1764Rd = new RunnableC1764Rd(c1837ae2, str2, strU, j4, j6, j10, jU, jP, z2, i2, i3);
                                        ?? r1 = ls;
                                        r1.post(runnableC1764Rd);
                                        j9 = j4;
                                        c1837ae = r1;
                                    } catch (Throwable th2) {
                                        th = th2;
                                        c1837ae2 = this;
                                        str2 = str;
                                        throw th;
                                    }
                                } catch (Throwable th3) {
                                    th = th3;
                                    z = false;
                                    c1837ae2 = this;
                                    str2 = str;
                                    throw th;
                                }
                            } else {
                                z = z3;
                                j4 = jM1;
                                j5 = jLongValue;
                                j = jLongValue2;
                                j2 = jIntValue;
                                j6 = jO1;
                                c1837ae = c1837ae2;
                            }
                            if (j4 >= j6) {
                                com.google.android.gms.ads.internal.util.client.c.b.post(new RunnableC1782Ud(this, str, strU, j6));
                                return true;
                            }
                            try {
                                C1837ae c1837ae3 = this;
                                str2 = str;
                                if (c1837ae3.d.k >= j2 && j4 > 0) {
                                    return true;
                                }
                                j3 = j5;
                                c1837ae = c1837ae3;
                            } catch (Throwable th4) {
                                th = th4;
                                c1837ae2 = c1837ae;
                            }
                        } else {
                            z = z3;
                            j = jLongValue2;
                            j2 = jIntValue;
                            j3 = jLongValue;
                            c1837ae = c1837ae2;
                        }
                        try {
                            c1837ae.wait(j3);
                        } catch (InterruptedException unused) {
                            throw new IOException("Wait interrupted.");
                        }
                    } catch (Throwable th5) {
                        th = th5;
                        z = z3;
                        c1837ae2 = c1837ae2;
                    }
                }
                try {
                    throw th;
                } catch (Exception e) {
                    e = e;
                    com.google.android.gms.ads.internal.util.client.i.h("Failed to preload url " + str2 + " Exception: " + e.getMessage());
                    com.google.android.gms.ads.internal.j.C.h.g("VideoStreamExoPlayerCache.preload", e);
                    c1837ae2.j();
                    c1837ae2.m(str2, strU, "error", v("error", e));
                    return z;
                }
                jLongValue = j3;
                z3 = z;
                jIntValue = j2;
                jLongValue2 = j;
                c1837ae2 = c1837ae;
            }
        } catch (Exception e2) {
            e = e2;
            z = z3;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final boolean t(String str, String[] strArr, C1746Od c1746Od) {
        this.e = str;
        this.h = c1746Od;
        String strU = u(str);
        try {
            Uri[] uriArr = new Uri[strArr.length];
            for (int i = 0; i < strArr.length; i++) {
                uriArr[i] = Uri.parse(strArr[i]);
            }
            C2143he c2143he = this.d;
            c2143he.getClass();
            c2143he.q(uriArr, ByteBuffer.allocate(0), false);
            InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.c.get();
            if (interfaceC2529qe != null) {
                interfaceC2529qe.P(strU, this);
            }
            com.google.android.gms.ads.internal.j.C.k.getClass();
            this.i = System.currentTimeMillis();
            this.j = -1L;
            com.google.android.gms.ads.internal.util.F.l.postDelayed(new RunnableC1989e(this, 18), 0L);
            return true;
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.h("Failed to preload url " + str + " Exception: " + e.getMessage());
            com.google.android.gms.ads.internal.j.C.h.g("VideoStreamExoPlayerCache.preload", e);
            j();
            m(str, strU, "error", v("error", e));
            return false;
        }
    }
}
