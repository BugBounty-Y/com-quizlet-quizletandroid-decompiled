package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class W8 extends AbstractC2771w5 implements Y8 {
    @Override // com.google.android.gms.internal.ads.Y8
    public final void I1(Bundle bundle) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, bundle);
        d4(33, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final List c() {
        Parcel parcelY3 = Y3(3, f3());
        ArrayList arrayList = parcelY3.readArrayList(AbstractC2857y5.a);
        parcelY3.recycle();
        return arrayList;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final List d() {
        Parcel parcelY3 = Y3(23, f3());
        ArrayList arrayList = parcelY3.readArrayList(AbstractC2857y5.a);
        parcelY3.recycle();
        return arrayList;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final com.google.android.gms.ads.internal.client.v0 g() {
        Parcel parcelY3 = Y3(11, f3());
        com.google.android.gms.ads.internal.client.v0 v0VarE4 = com.google.android.gms.ads.internal.client.u0.e4(parcelY3.readStrongBinder());
        parcelY3.recycle();
        return v0VarE4;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final com.google.android.gms.ads.internal.client.s0 h() {
        Parcel parcelY3 = Y3(31, f3());
        com.google.android.gms.ads.internal.client.s0 s0VarE4 = Ug.e4(parcelY3.readStrongBinder());
        parcelY3.recycle();
        return s0VarE4;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final com.google.android.gms.dynamic.a k() {
        return assistantMode.refactored.a.h(Y3(19, f3()));
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final com.google.android.gms.dynamic.a l() {
        return assistantMode.refactored.a.h(Y3(18, f3()));
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String m() {
        Parcel parcelY3 = Y3(7, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final InterfaceC2860y8 n() {
        InterfaceC2860y8 c2817x8;
        Parcel parcelY3 = Y3(5, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c2817x8 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeAdImage");
            c2817x8 = iInterfaceQueryLocalInterface instanceof InterfaceC2860y8 ? (InterfaceC2860y8) iInterfaceQueryLocalInterface : new C2817x8(strongBinder);
        }
        parcelY3.recycle();
        return c2817x8;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String o() {
        Parcel parcelY3 = Y3(6, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String p() {
        Parcel parcelY3 = Y3(2, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String s() {
        Parcel parcelY3 = Y3(9, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String x() {
        Parcel parcelY3 = Y3(4, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final String z() {
        Parcel parcelY3 = Y3(10, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final double zze() {
        Parcel parcelY3 = Y3(8, f3());
        double d = parcelY3.readDouble();
        parcelY3.recycle();
        return d;
    }

    @Override // com.google.android.gms.internal.ads.Y8
    public final InterfaceC2645t8 zzi() {
        InterfaceC2645t8 c2559r8;
        Parcel parcelY3 = Y3(14, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c2559r8 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IAttributionInfo");
            c2559r8 = iInterfaceQueryLocalInterface instanceof InterfaceC2645t8 ? (InterfaceC2645t8) iInterfaceQueryLocalInterface : new C2559r8(strongBinder);
        }
        parcelY3.recycle();
        return c2559r8;
    }
}
