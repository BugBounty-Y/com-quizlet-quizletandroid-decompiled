package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.a0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1816a0 implements InterfaceC2122h0 {
    public final InterfaceC2122h0 a;

    public AbstractC1816a0(InterfaceC2122h0 interfaceC2122h0) {
        this.a = interfaceC2122h0;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public C2078g0 b(long j) {
        return this.a.b(j);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return this.a.g();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public long zza() {
        return this.a.zza();
    }
}
