package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public final class I8 extends AbstractC2771w5 implements J8 {
    public I8(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.formats.client.INativeCustomTemplateAd", 0);
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final void T(String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        d4(5, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final boolean U(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        Parcel parcelY3 = Y3(10, parcelF3);
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final boolean W(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        Parcel parcelY3 = Y3(17, parcelF3);
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final InterfaceC2860y8 Z(String str) {
        InterfaceC2860y8 c2817x8;
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        Parcel parcelY3 = Y3(2, parcelF3);
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

    @Override // com.google.android.gms.internal.ads.J8
    public final InterfaceC2774w8 f() {
        InterfaceC2774w8 c2731v8;
        Parcel parcelY3 = Y3(16, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c2731v8 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IMediaContent");
            c2731v8 = iInterfaceQueryLocalInterface instanceof InterfaceC2774w8 ? (InterfaceC2774w8) iInterfaceQueryLocalInterface : new C2731v8(strongBinder);
        }
        parcelY3.recycle();
        return c2731v8;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final com.google.android.gms.dynamic.a g() {
        return assistantMode.refactored.a.h(Y3(9, f3()));
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final void k() {
        d4(8, f3());
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final void l() {
        d4(15, f3());
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final List n() {
        Parcel parcelY3 = Y3(3, f3());
        ArrayList<String> arrayListCreateStringArrayList = parcelY3.createStringArrayList();
        parcelY3.recycle();
        return arrayListCreateStringArrayList;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final boolean p() {
        Parcel parcelY3 = Y3(12, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final String r3(String str) {
        Parcel parcelF3 = f3();
        parcelF3.writeString(str);
        Parcel parcelY3 = Y3(1, parcelF3);
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final void v() {
        d4(6, f3());
    }

    @Override // com.google.android.gms.internal.ads.J8
    public final String zzi() {
        Parcel parcelY3 = Y3(4, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }
}
