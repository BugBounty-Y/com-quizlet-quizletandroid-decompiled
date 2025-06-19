package com.google.android.gms.internal.ads;

import android.util.Pair;
import java.io.IOException;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class DD implements InterfaceC2266kF, InterfaceC2909zE {
    public final FD a;
    public final /* synthetic */ C2538qn b;

    public DD(C2538qn c2538qn, FD fd) {
        this.b = c2538qn;
        this.a = fd;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void a(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0, IOException iOException, boolean z) {
        Pair pairF = f(c2093gF);
        if (pairF != null) {
            ((Bo) this.b.j).b(new BD(this, pairF, ye, s0, iOException, z));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void b(int i, C2093gF c2093gF, androidx.compose.animation.core.S0 s0) {
        Pair pairF = f(c2093gF);
        if (pairF != null) {
            ((Bo) this.b.j).b(new C(this, pairF, s0, 11));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void c(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0) {
        Pair pairF = f(c2093gF);
        if (pairF != null) {
            ((Bo) this.b.j).b(new CD(this, pairF, ye, s0, 1));
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void d(int i, C2093gF c2093gF, final YE ye, final androidx.compose.animation.core.S0 s0, final int i2) {
        final Pair pairF = f(c2093gF);
        if (pairF != null) {
            ((Bo) this.b.j).b(new Runnable() { // from class: com.google.android.gms.internal.ads.AD
                @Override // java.lang.Runnable
                public final void run() {
                    WD wd = (WD) this.a.b.i;
                    Pair pair = pairF;
                    wd.d(((Integer) pair.first).intValue(), (C2093gF) pair.second, ye, s0, i2);
                }
            });
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2266kF
    public final void e(int i, C2093gF c2093gF, YE ye, androidx.compose.animation.core.S0 s0) {
        Pair pairF = f(c2093gF);
        if (pairF != null) {
            ((Bo) this.b.j).b(new CD(this, pairF, ye, s0, 0));
        }
    }

    public final Pair f(C2093gF c2093gF) {
        C2093gF c2093gFA;
        FD fd = this.a;
        C2093gF c2093gF2 = null;
        if (c2093gF != null) {
            int i = 0;
            while (true) {
                ArrayList arrayList = fd.c;
                if (i >= arrayList.size()) {
                    c2093gFA = null;
                    break;
                }
                if (((C2093gF) arrayList.get(i)).d == c2093gF.d) {
                    Object obj = fd.b;
                    int i2 = LD.k;
                    c2093gFA = c2093gF.a(Pair.create(obj, c2093gF.a));
                    break;
                }
                i++;
            }
            if (c2093gFA == null) {
                return null;
            }
            c2093gF2 = c2093gFA;
        }
        return Pair.create(Integer.valueOf(fd.d), c2093gF2);
    }
}
