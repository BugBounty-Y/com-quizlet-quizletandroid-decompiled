package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.InterfaceC1582a;
import java.util.LinkedList;

/* renamed from: com.google.android.gms.internal.ads.zg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2917zg implements InterfaceC2617sh, InterfaceC1582a, Jh, InterfaceC2189ih, Xg, Uh {
    public final com.google.android.gms.common.util.a a;
    public final C1880bd b;

    public C2917zg(com.google.android.gms.common.util.a aVar, C1880bd c1880bd) {
        this.a = aVar;
        this.b = c1880bd;
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void J0(C1849aq c1849aq) {
        com.google.android.gms.common.util.a aVar = this.a;
        C1880bd c1880bd = this.b;
        long jElapsedRealtime = aVar.elapsedRealtime();
        synchronized (c1880bd.d) {
            try {
                c1880bd.k = jElapsedRealtime;
                if (jElapsedRealtime != -1) {
                    c1880bd.b.a(c1880bd);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final void K() {
        C1880bd c1880bd = this.b;
        synchronized (c1880bd.d) {
            try {
                if (c1880bd.k != -1 && c1880bd.g == -1) {
                    c1880bd.g = c1880bd.a.elapsedRealtime();
                    c1880bd.b.a(c1880bd);
                }
                C2098gd c2098gd = c1880bd.b;
                synchronized (c2098gd.a) {
                    C2054fd c2054fd = c2098gd.d;
                    synchronized (c2054fd.f) {
                        c2054fd.j++;
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void S(boolean z) {
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void T0(T6 t6) {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void a() {
        C1880bd c1880bd = this.b;
        synchronized (c1880bd.d) {
            try {
                if (c1880bd.k != -1) {
                    LinkedList linkedList = c1880bd.c;
                    if (!linkedList.isEmpty()) {
                        C1836ad c1836ad = (C1836ad) linkedList.getLast();
                        if (c1836ad.b == -1) {
                            c1836ad.b = c1836ad.c.a.elapsedRealtime();
                            c1880bd.b.a(c1880bd);
                        }
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void b() {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void f() {
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void g() {
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void o(boolean z) {
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1582a
    public final void onAdClicked() {
        C1880bd c1880bd = this.b;
        synchronized (c1880bd.d) {
            if (c1880bd.k != -1) {
                C1836ad c1836ad = new C1836ad(c1880bd);
                c1836ad.a = c1880bd.a.elapsedRealtime();
                c1880bd.c.add(c1836ad);
                c1880bd.i++;
                C2098gd c2098gd = c1880bd.b;
                synchronized (c2098gd.a) {
                    C2054fd c2054fd = c2098gd.d;
                    synchronized (c2054fd.f) {
                        c2054fd.i++;
                    }
                }
                c2098gd.a(c1880bd);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void q() {
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void r(T6 t6) {
        C1880bd c1880bd = this.b;
        synchronized (c1880bd.d) {
            C2098gd c2098gd = c1880bd.b;
            synchronized (c2098gd.a) {
                c2098gd.d.b();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() {
        C1880bd c1880bd = this.b;
        synchronized (c1880bd.d) {
            try {
                if (c1880bd.k != -1) {
                    c1880bd.h = c1880bd.a.elapsedRealtime();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void v(BinderC1966dc binderC1966dc, String str, String str2) {
    }

    @Override // com.google.android.gms.internal.ads.Uh
    public final void z0(T6 t6) {
        C1880bd c1880bd = this.b;
        synchronized (c1880bd.d) {
            C2098gd c2098gd = c1880bd.b;
            synchronized (c2098gd.a) {
                c2098gd.d.b();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void zze() {
    }
}
