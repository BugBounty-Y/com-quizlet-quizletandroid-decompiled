package com.google.android.gms.internal.ads;

import android.content.Intent;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;

/* renamed from: com.google.android.gms.internal.ads.Ab, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1660Ab extends AbstractC2771w5 implements InterfaceC1672Cb {
    public C1660Ab(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.overlay.client.IAdOverlay", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void B2(Bundle bundle) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, bundle);
        Parcel parcelY3 = Y3(6, parcelF3);
        if (parcelY3.readInt() != 0) {
            bundle.readFromParcel(parcelY3);
        }
        parcelY3.recycle();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void H1(int i, String[] strArr, int[] iArr) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        parcelF3.writeStringArray(strArr);
        parcelF3.writeIntArray(iArr);
        d4(15, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void c() {
        d4(7, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void d() {
        d4(14, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void l() {
        d4(8, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void m1(int i, int i2, Intent intent) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        parcelF3.writeInt(i2);
        AbstractC2857y5.c(parcelF3, intent);
        d4(12, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void p() {
        d4(2, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void p2(Bundle bundle) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, bundle);
        d4(1, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void s() {
        d4(3, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final boolean s3() {
        Parcel parcelY3 = Y3(11, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void v() {
        d4(5, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void v2(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(13, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void w() {
        d4(4, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void y() {
        d4(9, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1672Cb
    public final void zzi() {
        d4(10, f3());
    }
}
