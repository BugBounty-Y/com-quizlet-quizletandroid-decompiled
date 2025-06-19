package com.google.android.gms.ads.internal.client;

import android.content.Context;
import com.amazon.device.ads.DTBAdSize;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.BinderC2739va;

/* renamed from: com.google.android.gms.ads.internal.client.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1600j extends AbstractC1612p {
    public final /* synthetic */ Context b;
    public final /* synthetic */ zzr c;
    public final /* synthetic */ String d;
    public final /* synthetic */ BinderC2739va e;
    public final /* synthetic */ C1608n f;

    public C1600j(C1608n c1608n, Context context, zzr zzrVar, String str, BinderC2739va binderC2739va) {
        this.b = context;
        this.c = zzrVar;
        this.d = str;
        this.e = binderC2739va;
        this.f = c1608n;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object a() {
        C1608n.y(this.b, DTBAdSize.AAX_INTERSTITIAL_AD_SIZE);
        return new J0();
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        return s.F0(new com.google.android.gms.dynamic.b(this.b), this.c, this.d, this.e, ModuleDescriptor.MODULE_VERSION);
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final /* bridge */ /* synthetic */ Object c() {
        G0 g0 = (G0) this.f.a;
        BinderC2739va binderC2739va = this.e;
        return g0.v(this.b, this.c, this.d, binderC2739va, 2);
    }
}
