package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzfp;

/* renamed from: com.google.android.gms.internal.ads.sr, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2627sr extends AbstractBinderC1822a6 {
    public final /* synthetic */ C1985dw a;
    public final /* synthetic */ zzfp b;
    public final /* synthetic */ C2670tr c;

    public BinderC2627sr(C2670tr c2670tr, C1985dw c1985dw, zzfp zzfpVar) {
        this.a = c1985dw;
        this.b = zzfpVar;
        this.c = c2670tr;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1866b6
    public final void F(int i) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1866b6
    public final void a0(zze zzeVar) {
        com.google.android.gms.ads.internal.util.client.i.h("Failed to load app open ad with error parcel: " + zzeVar.b().toString() + " for ad unit: " + this.b.a);
        C2670tr.i(this.c, zzeVar);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1866b6
    public final void a4(Y5 y5) {
        this.a.g(y5);
    }
}
