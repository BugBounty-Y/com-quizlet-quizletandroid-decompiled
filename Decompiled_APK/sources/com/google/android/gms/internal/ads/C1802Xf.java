package com.google.android.gms.internal.ads;

import android.view.View;

/* renamed from: com.google.android.gms.internal.ads.Xf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1802Xf implements CC {
    public final /* synthetic */ int a;
    public final com.google.firebase.messaging.u b;

    public /* synthetic */ C1802Xf(com.google.firebase.messaging.u uVar, int i) {
        this.a = i;
        this.b = uVar;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                View view = (View) this.b.b;
                AbstractC1981ds.s(view);
                return view;
            case 1:
                Wp wp = (Wp) this.b.c;
                AbstractC1981ds.s(wp);
                return wp;
            case 2:
                return (InterfaceC2316lg) this.b.a;
            default:
                return (InterfaceC2529qe) this.b.d;
        }
    }
}
