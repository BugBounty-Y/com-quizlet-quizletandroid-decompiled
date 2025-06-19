package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.IBinder;
import android.os.Parcel;
import java.util.ArrayList;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.Ga, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1695Ga extends AbstractC2771w5 implements InterfaceC1707Ia {
    public C1695Ga(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.mediation.client.IUnifiedNativeAdMapper", 0);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final boolean K() {
        Parcel parcelY3 = Y3(17, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final void a3(com.google.android.gms.dynamic.a aVar, com.google.android.gms.dynamic.a aVar2, com.google.android.gms.dynamic.a aVar3) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.e(parcelF3, aVar2);
        AbstractC2857y5.e(parcelF3, aVar3);
        d4(21, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String c() {
        Parcel parcelY3 = Y3(9, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final List d() {
        Parcel parcelY3 = Y3(3, f3());
        ArrayList arrayList = parcelY3.readArrayList(AbstractC2857y5.a);
        parcelY3.recycle();
        return arrayList;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final float f() {
        Parcel parcelY3 = Y3(23, f3());
        float f = parcelY3.readFloat();
        parcelY3.recycle();
        return f;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final float g() {
        Parcel parcelY3 = Y3(24, f3());
        float f = parcelY3.readFloat();
        parcelY3.recycle();
        return f;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final float h() {
        Parcel parcelY3 = Y3(25, f3());
        float f = parcelY3.readFloat();
        parcelY3.recycle();
        return f;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final com.google.android.gms.ads.internal.client.v0 i() {
        Parcel parcelY3 = Y3(11, f3());
        com.google.android.gms.ads.internal.client.v0 v0VarE4 = com.google.android.gms.ads.internal.client.u0.e4(parcelY3.readStrongBinder());
        parcelY3.recycle();
        return v0VarE4;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final boolean j0() {
        Parcel parcelY3 = Y3(18, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final InterfaceC2860y8 k() {
        Parcel parcelY3 = Y3(5, f3());
        InterfaceC2860y8 interfaceC2860y8E4 = BinderC2474p8.e4(parcelY3.readStrongBinder());
        parcelY3.recycle();
        return interfaceC2860y8E4;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final com.google.android.gms.dynamic.a l() {
        return assistantMode.refactored.a.h(Y3(13, f3()));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final com.google.android.gms.dynamic.a m() {
        return assistantMode.refactored.a.h(Y3(14, f3()));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final InterfaceC2645t8 n() {
        Parcel parcelY3 = Y3(12, f3());
        InterfaceC2645t8 interfaceC2645t8E4 = AbstractBinderC2602s8.e4(parcelY3.readStrongBinder());
        parcelY3.recycle();
        return interfaceC2645t8E4;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String o() {
        Parcel parcelY3 = Y3(7, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String p() {
        Parcel parcelY3 = Y3(4, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String s() {
        Parcel parcelY3 = Y3(10, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final void u0(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(20, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String w() {
        Parcel parcelY3 = Y3(6, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final com.google.android.gms.dynamic.a x() {
        return assistantMode.refactored.a.h(Y3(15, f3()));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final void y() {
        d4(19, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final void y1(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(22, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final String z() {
        Parcel parcelY3 = Y3(2, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final double zze() {
        Parcel parcelY3 = Y3(8, f3());
        double d = parcelY3.readDouble();
        parcelY3.recycle();
        return d;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1707Ia
    public final Bundle zzi() {
        Parcel parcelY3 = Y3(16, f3());
        Bundle bundle = (Bundle) AbstractC2857y5.a(parcelY3, Bundle.CREATOR);
        parcelY3.recycle();
        return bundle;
    }
}
