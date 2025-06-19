package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* loaded from: classes2.dex */
public final class Es extends AbstractC2771w5 implements Fs {
    @Override // com.google.android.gms.internal.ads.Fs
    public final void B1(byte[] bArr) {
        Parcel parcelF3 = f3();
        parcelF3.writeByteArray(bArr);
        d4(5, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void e(int i) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        d4(7, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void f() {
        d4(3, f3());
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void o0() {
        Parcel parcelF3 = f3();
        parcelF3.writeIntArray(null);
        d4(4, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void s2(int i) {
        Parcel parcelF3 = f3();
        parcelF3.writeInt(i);
        d4(6, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void y3(com.google.android.gms.dynamic.b bVar, String str) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, bVar);
        parcelF3.writeString(str);
        parcelF3.writeString(null);
        d4(8, parcelF3);
    }
}
