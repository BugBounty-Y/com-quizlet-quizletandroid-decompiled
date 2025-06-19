package com.google.android.gms.internal.ads;

import android.net.Uri;
import androidx.compose.foundation.lazy.layout.C0429a;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: com.google.android.gms.internal.ads.Zd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1812Zd extends AbstractC1794Wd implements FC {
    public static final AtomicInteger o = new AtomicInteger(0);
    public String d;
    public final C1668Bd e;
    public boolean f;
    public final androidx.compose.foundation.gestures.l1 g;
    public final C0429a h;
    public ByteBuffer i;
    public boolean j;
    public final Object k;
    public final String l;
    public final int m;
    public boolean n;

    public C1812Zd(InterfaceC2529qe interfaceC2529qe, C1668Bd c1668Bd) {
        super(interfaceC2529qe);
        this.e = c1668Bd;
        this.g = new androidx.compose.foundation.gestures.l1(8);
        this.h = new C0429a();
        this.k = new Object();
        String strW = interfaceC2529qe.w();
        this.l = (String) (strW == null ? C2458ot.a : new C2801wt(strW)).b();
        this.m = interfaceC2529qe.f();
        o.incrementAndGet();
    }

    @Override // com.google.android.gms.internal.ads.FC
    public final void b(AbstractC2802wu abstractC2802wu, C2891yx c2891yx, boolean z) {
        if (abstractC2802wu instanceof C2807wz) {
            ((ArrayList) this.g.c).add((C2807wz) abstractC2802wu);
        }
    }

    @Override // com.google.android.gms.internal.ads.FC
    public final void c(C2891yx c2891yx, boolean z) {
    }

    @Override // com.google.android.gms.internal.ads.FC
    public final void f(C2891yx c2891yx, boolean z, int i) {
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final void j() {
        o.decrementAndGet();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final void l() {
        this.f = true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r21v0, types: [com.google.android.gms.internal.ads.FC, com.google.android.gms.internal.ads.Wd, com.google.android.gms.internal.ads.Zd] */
    /* JADX WARN: Type inference failed for: r2v10 */
    /* JADX WARN: Type inference failed for: r2v11 */
    /* JADX WARN: Type inference failed for: r2v15 */
    /* JADX WARN: Type inference failed for: r2v16 */
    /* JADX WARN: Type inference failed for: r2v3, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r2v4 */
    /* JADX WARN: Type inference failed for: r2v8 */
    /* JADX WARN: Type inference failed for: r2v9 */
    /* JADX WARN: Type inference failed for: r4v2, types: [java.lang.StringBuilder] */
    /* JADX WARN: Type inference failed for: r4v25, types: [com.google.android.gms.internal.ads.Jd] */
    /* JADX WARN: Type inference failed for: r6v3, types: [java.lang.String] */
    /* JADX WARN: Type inference failed for: r6v4 */
    /* JADX WARN: Type inference failed for: r6v7, types: [java.lang.Object] */
    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final boolean r(String str) throws IOException {
        String str2;
        String str3;
        ?? r6;
        ?? r2;
        C2807wz c2807wz;
        long jCurrentTimeMillis;
        long jLongValue;
        long jLongValue2;
        int i;
        byte[] bArr;
        long j;
        long j2;
        String str4 = str;
        this.d = str4;
        String str5 = "error";
        String strConcat = "cache:".concat(String.valueOf(com.google.android.gms.ads.internal.util.client.c.a(str4, "MD5")));
        try {
            Fp fp = new Fp(7);
            String str6 = this.b;
            C1668Bd c1668Bd = this.e;
            c2807wz = new C2807wz(str6, c1668Bd.d, c1668Bd.e, true, fp);
            c2807wz.m(this);
            if (c1668Bd.i) {
                c2807wz = new C1716Jd(this.a, c2807wz, this.l, this.m);
            }
            c2807wz.c(new C2891yx(Uri.parse(str4), 0L, -1L));
            InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.c.get();
            if (interfaceC2529qe != null) {
                interfaceC2529qe.P(strConcat, this);
            }
            com.google.android.gms.ads.internal.j.C.k.getClass();
            jCurrentTimeMillis = System.currentTimeMillis();
            C2601s7 c2601s7 = AbstractC2773w7.F;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            jLongValue = ((Long) rVar.c.a(c2601s7)).longValue();
            jLongValue2 = ((Long) rVar.c.a(AbstractC2773w7.E)).longValue();
            this.i = ByteBuffer.allocate(c1668Bd.c);
            i = 8192;
            bArr = new byte[8192];
            j = jCurrentTimeMillis;
            str4 = str4;
        } catch (Exception e) {
            e = e;
            str2 = str4;
        }
        while (true) {
            try {
                int iD = c2807wz.d(0, bArr, Math.min(this.i.remaining(), i));
                r2 = -1;
                str3 = str5;
                if (iD == -1) {
                    try {
                        this.n = true;
                        com.google.android.gms.ads.internal.util.client.c.b.post(new RunnableC1782Ud((AbstractC1794Wd) this, str, strConcat, (int) this.h.c(this.i)));
                        return true;
                    } catch (Exception e2) {
                        e = e2;
                        r2 = str;
                    }
                } else {
                    try {
                        r2 = str;
                        r6 = this.k;
                        synchronized (r6) {
                            try {
                                if (this.f) {
                                    j2 = jCurrentTimeMillis;
                                } else {
                                    j2 = jCurrentTimeMillis;
                                    this.i.put(bArr, 0, iD);
                                }
                            } finally {
                            }
                        }
                        if (this.i.remaining() <= 0) {
                            u();
                            return true;
                        }
                        try {
                            if (this.f) {
                                throw new IOException("Precache abort at " + this.i.limit() + " bytes");
                            }
                            long jCurrentTimeMillis2 = System.currentTimeMillis();
                            if (jCurrentTimeMillis2 - j >= jLongValue) {
                                u();
                                j = jCurrentTimeMillis2;
                            }
                            if (jCurrentTimeMillis2 - j2 > 1000 * jLongValue2) {
                                throw new IOException("Timeout exceeded. Limit: " + jLongValue2 + " sec");
                            }
                            str5 = str3;
                            jCurrentTimeMillis = j2;
                            i = 8192;
                            str4 = r2;
                        } catch (Exception e3) {
                            e = e3;
                        }
                    } catch (Exception e4) {
                        e = e4;
                        r2 = r2;
                    }
                }
            } catch (Exception e5) {
                e = e5;
                str2 = str;
                str3 = str5;
                r2 = str2;
                r6 = str3;
                String strL = android.support.v4.media.session.a.l(e.getClass().getCanonicalName(), ":", e.getMessage());
                com.google.android.gms.ads.internal.util.client.i.h("Failed to preload url " + r2 + " Exception: " + strL);
                m(r2, strConcat, r6, strL);
                return false;
            }
            r6 = str3;
            String strL2 = android.support.v4.media.session.a.l(e.getClass().getCanonicalName(), ":", e.getMessage());
            com.google.android.gms.ads.internal.util.client.i.h("Failed to preload url " + r2 + " Exception: " + strL2);
            m(r2, strConcat, r6, strL2);
            return false;
        }
    }

    public final void u() {
        androidx.compose.foundation.gestures.l1 l1Var = this.g;
        Iterator it2 = ((ArrayList) l1Var.c).iterator();
        while (it2.hasNext()) {
            for (Map.Entry entry : ((C2807wz) it2.next()).zze().entrySet()) {
                try {
                    if ("content-length".equalsIgnoreCase((String) entry.getKey())) {
                        l1Var.b = Math.max(l1Var.b, Long.parseLong((String) ((List) entry.getValue()).get(0)));
                    }
                } catch (RuntimeException unused) {
                }
            }
            it2.remove();
        }
        int i = (int) l1Var.b;
        int iC = (int) this.h.c(this.i);
        int iPosition = this.i.position();
        int iRound = Math.round((iPosition / i) * iC);
        int i2 = C2143he.u.get();
        int i3 = C2143he.v.get();
        String str = this.d;
        com.google.android.gms.ads.internal.util.client.c.b.post(new RunnableC1770Sd(this, str, "cache:".concat(String.valueOf(com.google.android.gms.ads.internal.util.client.c.a(str, "MD5"))), iPosition, i, iRound, iC, iRound > 0, i2, i3));
    }
}
