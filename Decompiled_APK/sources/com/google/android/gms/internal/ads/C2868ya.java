package com.google.android.gms.internal.ads;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.ads.internal.client.zzm;
import java.util.ArrayList;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.ya, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2868ya extends AbstractC2771w5 implements InterfaceC2911za {
    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void E2(zzm zzmVar, String str) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzmVar);
        parcelF3.writeString(str);
        d4(11, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final boolean H() {
        Parcel parcelY3 = Y3(22, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void J2(boolean z) {
        Parcel parcelF3 = f3();
        ClassLoader classLoader = AbstractC2857y5.a;
        parcelF3.writeInt(z ? 1 : 0);
        d4(25, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final boolean L() {
        Parcel parcelY3 = Y3(13, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void N() {
        d4(9, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final C1683Ea O() {
        C1683Ea c1683Ea;
        Parcel parcelY3 = Y3(15, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c1683Ea = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.INativeAppInstallAdMapper");
            c1683Ea = iInterfaceQueryLocalInterface instanceof C1683Ea ? (C1683Ea) iInterfaceQueryLocalInterface : new C1683Ea(strongBinder, "com.google.android.gms.ads.internal.mediation.client.INativeAppInstallAdMapper", 0);
        }
        parcelY3.recycle();
        return c1683Ea;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void Q() {
        d4(12, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void U0() {
        d4(8, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void U3(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(37, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void W3(com.google.android.gms.dynamic.a aVar, zzm zzmVar, String str, String str2, InterfaceC1671Ca interfaceC1671Ca, zzbfv zzbfvVar, ArrayList arrayList) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzmVar);
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC2857y5.e(parcelF3, interfaceC1671Ca);
        AbstractC2857y5.c(parcelF3, zzbfvVar);
        parcelF3.writeStringList(arrayList);
        d4(14, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void Z0(com.google.android.gms.dynamic.a aVar, com.google.android.gms.ads.internal.client.zzr zzrVar, zzm zzmVar, String str, String str2, InterfaceC1671Ca interfaceC1671Ca) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzrVar);
        AbstractC2857y5.c(parcelF3, zzmVar);
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC2857y5.e(parcelF3, interfaceC1671Ca);
        d4(6, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void c4(com.google.android.gms.dynamic.a aVar, zzm zzmVar, String str, String str2, InterfaceC1671Ca interfaceC1671Ca) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzmVar);
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC2857y5.e(parcelF3, interfaceC1671Ca);
        d4(7, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final C1689Fa d0() {
        C1689Fa c1689Fa;
        Parcel parcelY3 = Y3(16, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c1689Fa = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.INativeContentAdMapper");
            c1689Fa = iInterfaceQueryLocalInterface instanceof C1689Fa ? (C1689Fa) iInterfaceQueryLocalInterface : new C1689Fa(strongBinder, "com.google.android.gms.ads.internal.mediation.client.INativeContentAdMapper", 0);
        }
        parcelY3.recycle();
        return c1689Fa;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void d2(com.google.android.gms.dynamic.a aVar, zzm zzmVar, String str, InterfaceC1671Ca interfaceC1671Ca) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzmVar);
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, interfaceC1671Ca);
        d4(28, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void d3(com.google.android.gms.dynamic.a aVar, InterfaceC2226jc interfaceC2226jc, List list) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.e(parcelF3, interfaceC2226jc);
        parcelF3.writeStringList(list);
        d4(23, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final com.google.android.gms.ads.internal.client.v0 g() {
        Parcel parcelY3 = Y3(26, f3());
        com.google.android.gms.ads.internal.client.v0 v0VarE4 = com.google.android.gms.ads.internal.client.u0.e4(parcelY3.readStrongBinder());
        parcelY3.recycle();
        return v0VarE4;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void h0() {
        d4(4, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final C1677Da i() {
        C1677Da c1677Da;
        Parcel parcelY3 = Y3(36, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c1677Da = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationInterscrollerAd");
            c1677Da = iInterfaceQueryLocalInterface instanceof C1677Da ? (C1677Da) iInterfaceQueryLocalInterface : new C1677Da(strongBinder);
        }
        parcelY3.recycle();
        return c1677Da;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final zzbrz k() {
        Parcel parcelY3 = Y3(33, f3());
        zzbrz zzbrzVar = (zzbrz) AbstractC2857y5.a(parcelY3, zzbrz.CREATOR);
        parcelY3.recycle();
        return zzbrzVar;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void k2(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(39, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final zzbrz l() {
        Parcel parcelY3 = Y3(34, f3());
        zzbrz zzbrzVar = (zzbrz) AbstractC2857y5.a(parcelY3, zzbrz.CREATOR);
        parcelY3.recycle();
        return zzbrzVar;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final com.google.android.gms.dynamic.a m() {
        return assistantMode.refactored.a.h(Y3(2, f3()));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final InterfaceC1707Ia n() {
        InterfaceC1707Ia c1695Ga;
        Parcel parcelY3 = Y3(27, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c1695Ga = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IUnifiedNativeAdMapper");
            c1695Ga = iInterfaceQueryLocalInterface instanceof InterfaceC1707Ia ? (InterfaceC1707Ia) iInterfaceQueryLocalInterface : new C1695Ga(strongBinder);
        }
        parcelY3.recycle();
        return c1695Ga;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void n0(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(21, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void n1(com.google.android.gms.dynamic.a aVar, zzm zzmVar, String str, InterfaceC1671Ca interfaceC1671Ca) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzmVar);
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, interfaceC1671Ca);
        d4(32, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void n2(com.google.android.gms.dynamic.a aVar, zzm zzmVar, String str, InterfaceC1671Ca interfaceC1671Ca) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzmVar);
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, interfaceC1671Ca);
        d4(38, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void n3(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(30, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void s0(com.google.android.gms.dynamic.a aVar, H9 h9, ArrayList arrayList) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.e(parcelF3, h9);
        parcelF3.writeTypedList(arrayList);
        d4(31, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void v() {
        d4(5, f3());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void x0(com.google.android.gms.dynamic.a aVar, com.google.android.gms.ads.internal.client.zzr zzrVar, zzm zzmVar, String str, String str2, InterfaceC1671Ca interfaceC1671Ca) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzrVar);
        AbstractC2857y5.c(parcelF3, zzmVar);
        parcelF3.writeString(str);
        parcelF3.writeString(str2);
        AbstractC2857y5.e(parcelF3, interfaceC1671Ca);
        d4(35, parcelF3);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void z3(com.google.android.gms.dynamic.a aVar, zzm zzmVar, InterfaceC2226jc interfaceC2226jc, String str) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzmVar);
        parcelF3.writeString(null);
        AbstractC2857y5.e(parcelF3, interfaceC2226jc);
        parcelF3.writeString(str);
        d4(10, parcelF3);
    }
}
