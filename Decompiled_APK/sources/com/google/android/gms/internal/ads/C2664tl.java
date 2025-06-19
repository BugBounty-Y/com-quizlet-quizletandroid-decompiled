package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.tl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2664tl extends com.google.android.gms.ads.interstitial.b {
    public final /* synthetic */ String c;
    public final /* synthetic */ String d;
    public final /* synthetic */ BinderC2707ul e;

    public C2664tl(BinderC2707ul binderC2707ul, String str, String str2) {
        this.c = str;
        this.d = str2;
        this.e = binderC2707ul;
    }

    @Override // com.google.android.gms.ads.w
    public final void a(com.google.android.gms.ads.l lVar) {
        this.e.i4(BinderC2707ul.h4(lVar), this.d);
    }

    @Override // com.google.android.gms.ads.w
    public final /* bridge */ /* synthetic */ void b(Object obj) {
        String str = this.c;
        String str2 = this.d;
        this.e.e4(str, str2, (com.google.android.gms.ads.interstitial.a) obj);
    }
}
