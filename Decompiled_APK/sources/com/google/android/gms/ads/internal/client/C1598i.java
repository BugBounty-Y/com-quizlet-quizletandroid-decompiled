package com.google.android.gms.ads.internal.client;

import android.content.Context;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;

/* renamed from: com.google.android.gms.ads.internal.client.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1598i extends AbstractC1612p {
    public final /* synthetic */ Context b;
    public final /* synthetic */ zzr c;
    public final /* synthetic */ String d;
    public final /* synthetic */ C1608n e;

    public C1598i(C1608n c1608n, Context context, zzr zzrVar, String str) {
        this.b = context;
        this.c = zzrVar;
        this.d = str;
        this.e = c1608n;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object a() {
        C1608n.y(this.b, "search");
        return new J0();
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        return s.j1(new com.google.android.gms.dynamic.b(this.b), this.c, this.d, ModuleDescriptor.MODULE_VERSION);
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final /* bridge */ /* synthetic */ Object c() {
        return ((G0) this.e.a).v(this.b, this.c, this.d, null, 3);
    }
}
