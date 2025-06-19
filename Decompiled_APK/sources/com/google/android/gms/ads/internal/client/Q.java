package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.dynamite.descriptors.com.google.android.gms.ads.dynamite.ModuleDescriptor;
import com.google.android.gms.internal.ads.A8;
import com.google.android.gms.internal.ads.AbstractBinderC1666Bb;
import com.google.android.gms.internal.ads.AbstractBinderC1781Uc;
import com.google.android.gms.internal.ads.AbstractBinderC2398nc;
import com.google.android.gms.internal.ads.AbstractC2771w5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.B8;
import com.google.android.gms.internal.ads.BinderC2408nm;
import com.google.android.gms.internal.ads.C1660Ab;
import com.google.android.gms.internal.ads.C1775Tc;
import com.google.android.gms.internal.ads.C2355mc;
import com.google.android.gms.internal.ads.C2740vb;
import com.google.android.gms.internal.ads.C8;
import com.google.android.gms.internal.ads.InterfaceC1672Cb;
import com.google.android.gms.internal.ads.InterfaceC1787Vc;
import com.google.android.gms.internal.ads.InterfaceC2441oc;
import com.google.android.gms.internal.ads.InterfaceC2783wb;
import com.google.android.gms.internal.ads.InterfaceC2825xa;

/* loaded from: classes2.dex */
public final class Q extends AbstractC2771w5 implements S {
    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC1672Cb D(com.google.android.gms.dynamic.a aVar) {
        InterfaceC1672Cb c1660Ab;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        Parcel parcelY3 = Y3(8, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        int i = AbstractBinderC1666Bb.a;
        if (strongBinder == null) {
            c1660Ab = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.overlay.client.IAdOverlay");
            c1660Ab = iInterfaceQueryLocalInterface instanceof InterfaceC1672Cb ? (InterfaceC1672Cb) iInterfaceQueryLocalInterface : new C1660Ab(strongBinder);
        }
        parcelY3.recycle();
        return c1660Ab;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC2783wb D1(com.google.android.gms.dynamic.a aVar, InterfaceC2825xa interfaceC2825xa, int i) {
        InterfaceC2783wb c2740vb;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.e(parcelF3, interfaceC2825xa);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(15, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        int i2 = BinderC2408nm.h;
        if (strongBinder == null) {
            c2740vb = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.offline.IOfflineUtils");
            c2740vb = iInterfaceQueryLocalInterface instanceof InterfaceC2783wb ? (InterfaceC2783wb) iInterfaceQueryLocalInterface : new C2740vb(strongBinder);
        }
        parcelY3.recycle();
        return c2740vb;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final K F0(com.google.android.gms.dynamic.a aVar, zzr zzrVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        K i2;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzrVar);
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, interfaceC2825xa);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(2, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            i2 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdManager");
            i2 = iInterfaceQueryLocalInterface instanceof K ? (K) iInterfaceQueryLocalInterface : new I(strongBinder);
        }
        parcelY3.recycle();
        return i2;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC1613p0 G2(com.google.android.gms.dynamic.a aVar, InterfaceC2825xa interfaceC2825xa, int i) {
        InterfaceC1613p0 c1611o0;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.e(parcelF3, interfaceC2825xa);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(17, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            c1611o0 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IOutOfContextTester");
            c1611o0 = iInterfaceQueryLocalInterface instanceof InterfaceC1613p0 ? (InterfaceC1613p0) iInterfaceQueryLocalInterface : new C1611o0(strongBinder);
        }
        parcelY3.recycle();
        return c1611o0;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final C8 P1(com.google.android.gms.dynamic.a aVar, com.google.android.gms.dynamic.a aVar2) {
        C8 a8;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.e(parcelF3, aVar2);
        Parcel parcelY3 = Y3(5, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        int i = B8.a;
        if (strongBinder == null) {
            a8 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.INativeAdViewDelegate");
            a8 = iInterfaceQueryLocalInterface instanceof C8 ? (C8) iInterfaceQueryLocalInterface : new A8(strongBinder);
        }
        parcelY3.recycle();
        return a8;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC1585b0 V2(com.google.android.gms.dynamic.a aVar, int i) {
        InterfaceC1585b0 z;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(9, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            z = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IMobileAdsSettingManager");
            z = iInterfaceQueryLocalInterface instanceof InterfaceC1585b0 ? (InterfaceC1585b0) iInterfaceQueryLocalInterface : new Z(strongBinder);
        }
        parcelY3.recycle();
        return z;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final K a1(com.google.android.gms.dynamic.a aVar, zzr zzrVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        K i2;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzrVar);
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, interfaceC2825xa);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(1, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            i2 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdManager");
            i2 = iInterfaceQueryLocalInterface instanceof K ? (K) iInterfaceQueryLocalInterface : new I(strongBinder);
        }
        parcelY3.recycle();
        return i2;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final G b1(com.google.android.gms.dynamic.a aVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        G e;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, interfaceC2825xa);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(3, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            e = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdLoaderBuilder");
            e = iInterfaceQueryLocalInterface instanceof G ? (G) iInterfaceQueryLocalInterface : new E(strongBinder);
        }
        parcelY3.recycle();
        return e;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final K j1(com.google.android.gms.dynamic.a aVar, zzr zzrVar, String str, int i) {
        K i2;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzrVar);
        parcelF3.writeString(str);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(10, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            i2 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdManager");
            i2 = iInterfaceQueryLocalInterface instanceof K ? (K) iInterfaceQueryLocalInterface : new I(strongBinder);
        }
        parcelY3.recycle();
        return i2;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC1787Vc u3(com.google.android.gms.dynamic.a aVar, InterfaceC2825xa interfaceC2825xa, int i) {
        InterfaceC1787Vc c1775Tc;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.e(parcelF3, interfaceC2825xa);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(14, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        int i2 = AbstractBinderC1781Uc.a;
        if (strongBinder == null) {
            c1775Tc = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.signals.ISignalGenerator");
            c1775Tc = iInterfaceQueryLocalInterface instanceof InterfaceC1787Vc ? (InterfaceC1787Vc) iInterfaceQueryLocalInterface : new C1775Tc(strongBinder);
        }
        parcelY3.recycle();
        return c1775Tc;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final K v1(com.google.android.gms.dynamic.a aVar, zzr zzrVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        K i2;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        AbstractC2857y5.c(parcelF3, zzrVar);
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, interfaceC2825xa);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(13, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        if (strongBinder == null) {
            i2 = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdManager");
            i2 = iInterfaceQueryLocalInterface instanceof K ? (K) iInterfaceQueryLocalInterface : new I(strongBinder);
        }
        parcelY3.recycle();
        return i2;
    }

    @Override // com.google.android.gms.ads.internal.client.S
    public final InterfaceC2441oc x2(com.google.android.gms.dynamic.a aVar, String str, InterfaceC2825xa interfaceC2825xa, int i) {
        InterfaceC2441oc c2355mc;
        Parcel parcelF3 = f3();
        AbstractC2857y5.e(parcelF3, aVar);
        parcelF3.writeString(str);
        AbstractC2857y5.e(parcelF3, interfaceC2825xa);
        parcelF3.writeInt(ModuleDescriptor.MODULE_VERSION);
        Parcel parcelY3 = Y3(12, parcelF3);
        IBinder strongBinder = parcelY3.readStrongBinder();
        int i2 = AbstractBinderC2398nc.a;
        if (strongBinder == null) {
            c2355mc = null;
        } else {
            IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.rewarded.client.IRewardedAd");
            c2355mc = iInterfaceQueryLocalInterface instanceof InterfaceC2441oc ? (InterfaceC2441oc) iInterfaceQueryLocalInterface : new C2355mc(strongBinder);
        }
        parcelY3.recycle();
        return c2355mc;
    }
}
