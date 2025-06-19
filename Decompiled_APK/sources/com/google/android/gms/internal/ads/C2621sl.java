package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.sl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2621sl extends com.google.android.gms.ads.d {
    public final /* synthetic */ String b;
    public final /* synthetic */ com.google.android.gms.ads.i c;
    public final /* synthetic */ String d;
    public final /* synthetic */ BinderC2707ul e;

    public C2621sl(BinderC2707ul binderC2707ul, String str, com.google.android.gms.ads.i iVar, String str2) {
        this.b = str;
        this.c = iVar;
        this.d = str2;
        this.e = binderC2707ul;
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdFailedToLoad(com.google.android.gms.ads.l lVar) {
        this.e.i4(BinderC2707ul.h4(lVar), this.d);
    }

    @Override // com.google.android.gms.ads.d
    public final void onAdLoaded() {
        com.google.android.gms.ads.i iVar = this.c;
        this.e.e4(this.b, this.d, iVar);
    }
}
