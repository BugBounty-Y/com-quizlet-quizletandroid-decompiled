package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.InterfaceC1866b6;

/* loaded from: classes2.dex */
public final class I extends AbstractC2771w5 implements K {
    public I(IBinder iBinder) {
        super(iBinder, "com.google.android.gms.ads.internal.client.IAdManager", 0);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A0(P p) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, p);
        d4(8, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A1(zzr zzrVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzrVar);
        d4(13, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void A3(InterfaceC1619u interfaceC1619u) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, interfaceC1619u);
        d4(20, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean F3() {
        Parcel parcelY3 = Y3(23, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean I2(zzm zzmVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzmVar);
        Parcel parcelY3 = Y3(4, parcelF3);
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void K() {
        d4(6, f3());
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void M0(V v) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, v);
        d4(45, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void N1(InterfaceC1622x interfaceC1622x) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, interfaceC1622x);
        d4(7, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void P() {
        d4(5, f3());
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void W1(zzfw zzfwVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzfwVar);
        d4(29, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void X3(boolean z) {
        Parcel parcelF3 = f3();
        ClassLoader classLoader = AbstractC2857y5.a;
        parcelF3.writeInt(z ? 1 : 0);
        d4(22, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void Y0(zzm zzmVar, A a) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.c(parcelF3, zzmVar);
        AbstractC2857y5.e(parcelF3, a);
        d4(43, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void c3(boolean z) {
        Parcel parcelF3 = f3();
        ClassLoader classLoader = AbstractC2857y5.a;
        parcelF3.writeInt(z ? 1 : 0);
        d4(34, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void g3(InterfaceC1866b6 interfaceC1866b6) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, interfaceC1866b6);
        d4(40, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final zzr h() {
        Parcel parcelY3 = Y3(12, f3());
        zzr zzrVar = (zzr) AbstractC2857y5.a(parcelY3, zzr.CREATOR);
        parcelY3.recycle();
        return zzrVar;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final P i() {
        P o;
        Parcel parcelY3 = Y3(32, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            o = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAppEventListener");
            o = iInterfaceQueryLocalInterface instanceof P ? (P) iInterfaceQueryLocalInterface : new O(strongBinder);
        }
        parcelY3.recycle();
        return o;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void j0() {
        d4(11, f3());
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void j3(InterfaceC1609n0 interfaceC1609n0) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, interfaceC1609n0);
        d4(42, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final v0 k() {
        v0 t0Var;
        Parcel parcelY3 = Y3(26, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            t0Var = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IVideoController");
            t0Var = iInterfaceQueryLocalInterface instanceof v0 ? (v0) iInterfaceQueryLocalInterface : new t0(strongBinder);
        }
        parcelY3.recycle();
        return t0Var;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final com.google.android.gms.dynamic.a m() {
        return assistantMode.refactored.a.h(Y3(1, f3()));
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final s0 n() {
        s0 c1616r0;
        Parcel parcelY3 = Y3(41, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c1616r0 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IResponseInfo");
            c1616r0 = iInterfaceQueryLocalInterface instanceof s0 ? (s0) iInterfaceQueryLocalInterface : new C1616r0(strongBinder);
        }
        parcelY3.recycle();
        return c1616r0;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void s1(com.google.android.gms.dynamic.a aVar) {
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        d4(44, parcelF3);
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final boolean t3() {
        Parcel parcelY3 = Y3(46, f3());
        ClassLoader classLoader = AbstractC2857y5.a;
        boolean z = parcelY3.readInt() != 0;
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final String w() {
        Parcel parcelY3 = Y3(31, f3());
        String string = parcelY3.readString();
        parcelY3.recycle();
        return string;
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final void y() {
        d4(2, f3());
    }

    @Override // com.google.android.gms.ads.internal.client.K
    public final InterfaceC1622x zzi() {
        InterfaceC1622x c1620v;
        Parcel parcelY3 = Y3(33, f3());
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c1620v = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdListener");
            c1620v = iInterfaceQueryLocalInterface instanceof InterfaceC1622x ? (InterfaceC1622x) iInterfaceQueryLocalInterface : new C1620v(strongBinder);
        }
        parcelY3.recycle();
        return c1620v;
    }
}
