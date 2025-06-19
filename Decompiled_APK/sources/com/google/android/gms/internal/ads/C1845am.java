package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.am, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1845am implements InterfaceC2617sh, InterfaceC1840ah {
    public static final Object c = new Object();
    public static int d;
    public final com.google.android.gms.ads.internal.util.C a;
    public final C1976dm b;

    public C1845am(C1976dm c1976dm, com.google.android.gms.ads.internal.util.C c2) {
        this.b = c1976dm;
        this.a = c2;
    }

    public final void a(boolean z) {
        int i;
        int iIntValue;
        C2601s7 c2601s7 = AbstractC2773w7.g6;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && !this.a.k()) {
            Object obj = c;
            synchronized (obj) {
                i = d;
                iIntValue = ((Integer) rVar.c.a(AbstractC2773w7.h6)).intValue();
            }
            if (i < iIntValue) {
                C1976dm c1976dm = this.b;
                Iq iqV = c1976dm.e.v(new Bundle());
                iqV.a(new Qv(0, iqV, new androidx.appcompat.app.K(c1976dm, z)), AbstractC2270kd.g);
                synchronized (obj) {
                    d++;
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1840ah
    public final void m0(zze zzeVar) {
        a(false);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2617sh
    public final void s() {
        a(true);
    }
}
