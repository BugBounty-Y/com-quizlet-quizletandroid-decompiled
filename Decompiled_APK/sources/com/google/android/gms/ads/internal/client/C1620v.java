package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;

/* renamed from: com.google.android.gms.ads.internal.client.v, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1620v extends AbstractC2771w5 implements InterfaceC1622x {
    public C1620v(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.client.IAdListener", 0);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void g() {
        d4(3, f3());
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void h() {
        d4(7, f3());
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void i() {
        d4(5, f3());
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void j() {
        d4(1, f3());
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void q() {
        d4(6, f3());
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void r(zze zzeVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzeVar);
        d4(8, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void t() {
        d4(9, f3());
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void u(int i) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        d4(2, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.InterfaceC1622x
    public final void zzi() {
        d4(4, f3());
    }
}
