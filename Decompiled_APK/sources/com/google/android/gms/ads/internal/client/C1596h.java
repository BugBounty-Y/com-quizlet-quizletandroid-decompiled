package com.google.android.gms.ads.internal.client;

import android.content.Context;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.InterfaceC2825xa;

/* renamed from: com.google.android.gms.ads.internal.client.h, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1596h extends AbstractC1612p {
    public final /* synthetic */ Context b;
    public final /* synthetic */ zzr c;
    public final /* synthetic */ String d;
    public final /* synthetic */ InterfaceC2825xa e;
    public final /* synthetic */ C1608n f;

    public C1596h(C1608n c1608n, Context context, zzr zzrVar, String str, InterfaceC2825xa interfaceC2825xa) {
        this.b = context;
        this.c = zzrVar;
        this.d = str;
        this.e = interfaceC2825xa;
        this.f = c1608n;
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object a() {
        C1608n.y(this.b, "app_open");
        return new J0();
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final Object b(S s) {
        return s.v1(new com.google.android.gms.dynamic.b(this.b), this.c, this.d, this.e, ModuleDescriptor.MODULE_VERSION);
    }

    @Override // com.google.android.gms.ads.internal.client.AbstractC1612p
    public final /* bridge */ /* synthetic */ Object c() {
        return ((G0) this.f.a).v(this.b, this.c, this.d, this.e, 4);
    }
}
