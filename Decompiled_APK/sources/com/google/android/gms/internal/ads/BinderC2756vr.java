package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.AbstractBinderC1624z;
import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.vr, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2756vr extends AbstractBinderC1624z {
    public final /* synthetic */ C1985dw a;
    public final /* synthetic */ On b;
    public final /* synthetic */ C2670tr c;

    public BinderC2756vr(C2670tr c2670tr, C1985dw c1985dw, On on) {
        this.a = c1985dw;
        this.b = on;
        this.c = c2670tr;
    }

    @Override // com.google.android.gms.ads.internal.client.A
    public final void q() {
        this.a.g(this.b);
    }

    @Override // com.google.android.gms.ads.internal.client.A
    public final void t2(zze zzeVar) {
        String string = zzeVar.b().toString();
        C2670tr c2670tr = this.c;
        com.google.android.gms.ads.internal.util.client.i.h("Failed to load interstitial ad with error: " + string + " for ad unit: " + c2670tr.e.a);
        C2670tr.i(c2670tr, zzeVar);
    }
}
