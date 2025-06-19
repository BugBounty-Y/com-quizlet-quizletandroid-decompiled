package com.google.android.gms.internal.ads;

import java.util.HashMap;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class UC implements InterfaceC2522qD {
    public final C1963dG a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;
    public final long f;
    public final HashMap g;
    public long h;

    public UC() {
        C1963dG c1963dG = new C1963dG();
        h("bufferForPlaybackMs", 1000, "0", 0);
        h("bufferForPlaybackAfterRebufferMs", 2000, "0", 0);
        h("minBufferMs", 50000, "bufferForPlaybackMs", 1000);
        h("minBufferMs", 50000, "bufferForPlaybackAfterRebufferMs", 2000);
        h("maxBufferMs", 50000, "minBufferMs", 50000);
        h("backBufferDurationMs", 0, "0", 0);
        this.a = c1963dG;
        long jT = Yo.t(50000L);
        this.b = jT;
        this.c = jT;
        this.d = Yo.t(1000L);
        this.e = Yo.t(2000L);
        this.f = Yo.t(0L);
        this.g = new HashMap();
        this.h = -1L;
    }

    public static void h(String str, int i, String str2, int i2) {
        AbstractC1795We.G(i >= i2, android.support.v4.media.session.a.l(str, " cannot be less than ", str2));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final boolean a(C2479pD c2479pD) {
        int i;
        TC tc = (TC) this.g.get(c2479pD.a);
        tc.getClass();
        C1963dG c1963dG = this.a;
        synchronized (c1963dG) {
            i = c1963dG.b * 65536;
        }
        int iG = g();
        float f = c2479pD.c;
        long j = this.c;
        long jMin = this.b;
        if (f > 1.0f) {
            jMin = Math.min(Yo.s(jMin, f), j);
        }
        long jMax = Math.max(jMin, 500000L);
        long j2 = c2479pD.b;
        if (j2 < jMax) {
            boolean z = i < iG;
            tc.a = z;
            if (!z && j2 < 500000) {
                AbstractC2096gb.J("DefaultLoadControl", "Target buffer size reached with less than 500ms of buffered media data.");
            }
        } else if (j2 >= j || i >= iG) {
            tc.a = false;
        }
        return tc.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final void b(C1917cE c1917cE) {
        if (this.g.remove(c1917cE) != null) {
            boolean zIsEmpty = this.g.isEmpty();
            C1963dG c1963dG = this.a;
            if (!zIsEmpty) {
                c1963dG.a(g());
            } else {
                synchronized (c1963dG) {
                    c1963dG.a(0);
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final void c(C2479pD c2479pD, XF[] xfArr) {
        TC tc = (TC) this.g.get(c2479pD.a);
        tc.getClass();
        int length = xfArr.length;
        int i = 0;
        int i2 = 0;
        while (true) {
            int i3 = 13107200;
            if (i >= length) {
                break;
            }
            XF xf = xfArr[i];
            if (xf != null) {
                int i4 = xf.a().c;
                if (i4 != -1) {
                    if (i4 == 0) {
                        i3 = 144310272;
                    } else if (i4 != 1) {
                        i3 = i4 != 2 ? 131072 : 131072000;
                    }
                }
                i2 += i3;
            }
            i++;
        }
        tc.b = Math.max(13107200, i2);
        boolean zIsEmpty = this.g.isEmpty();
        C1963dG c1963dG = this.a;
        if (!zIsEmpty) {
            c1963dG.a(g());
        } else {
            synchronized (c1963dG) {
                c1963dG.a(0);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final boolean d(C2479pD c2479pD) {
        int i;
        boolean z = c2479pD.d;
        long jRound = c2479pD.b;
        float f = c2479pD.c;
        String str = Yo.a;
        if (f != 1.0f) {
            jRound = Math.round(jRound / f);
        }
        long jMin = z ? this.e : this.d;
        long j = c2479pD.e;
        if (j != -9223372036854775807L) {
            jMin = Math.min(j / 2, jMin);
        }
        if (jMin <= 0 || jRound >= jMin) {
            return true;
        }
        C1963dG c1963dG = this.a;
        synchronized (c1963dG) {
            i = c1963dG.b * 65536;
        }
        return i >= g();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final void e(C1917cE c1917cE) {
        if (this.g.remove(c1917cE) != null) {
            boolean zIsEmpty = this.g.isEmpty();
            C1963dG c1963dG = this.a;
            if (zIsEmpty) {
                synchronized (c1963dG) {
                    c1963dG.a(0);
                }
            } else {
                c1963dG.a(g());
            }
        }
        if (this.g.isEmpty()) {
            this.h = -1L;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final void f(C1917cE c1917cE) {
        long id = Thread.currentThread().getId();
        long j = this.h;
        boolean z = true;
        if (j != -1 && j != id) {
            z = false;
        }
        if (!z) {
            throw new IllegalStateException("Players that share the same LoadControl must share the same playback thread. See ExoPlayer.Builder.setPlaybackLooper(Looper).");
        }
        this.h = id;
        HashMap map = this.g;
        if (!map.containsKey(c1917cE)) {
            map.put(c1917cE, new TC());
        }
        TC tc = (TC) map.get(c1917cE);
        tc.getClass();
        tc.b = 13107200;
        tc.a = false;
    }

    public final int g() {
        Iterator it2 = this.g.values().iterator();
        int i = 0;
        while (it2.hasNext()) {
            i += ((TC) it2.next()).b;
        }
        return i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final C1963dG n() {
        return this.a;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final long zzb() {
        return this.f;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2522qD
    public final boolean zzi() {
        Iterator it2 = this.g.values().iterator();
        while (it2.hasNext()) {
            if (((TC) it2.next()).a) {
                return false;
            }
        }
        return true;
    }
}
