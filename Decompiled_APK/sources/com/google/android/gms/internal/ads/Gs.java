package com.google.android.gms.internal.ads;

import android.os.Parcel;

/* loaded from: classes2.dex */
public final class Gs extends AbstractBinderC2814x5 implements Fs {
    public Gs() {
        super("com.google.android.gms.gass.internal.clearcut.IGassClearcut");
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void B1(byte[] bArr) {
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        switch (i) {
            case 2:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                parcel.readString();
                AbstractC2857y5.b(parcel);
                break;
            case 3:
                break;
            case 4:
                parcel.createIntArray();
                AbstractC2857y5.b(parcel);
                break;
            case 5:
                parcel.createByteArray();
                AbstractC2857y5.b(parcel);
                break;
            case 6:
                parcel.readInt();
                AbstractC2857y5.b(parcel);
                break;
            case 7:
                parcel.readInt();
                AbstractC2857y5.b(parcel);
                break;
            case 8:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                parcel.readString();
                parcel.readString();
                AbstractC2857y5.b(parcel);
                break;
            default:
                return false;
        }
        parcel2.writeNoException();
        return true;
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void e(int i) {
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void f() {
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void o0() {
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void s2(int i) {
    }

    @Override // com.google.android.gms.internal.ads.Fs
    public final void y3(com.google.android.gms.dynamic.b bVar, String str) {
    }
}
