package com.google.android.gms.ads.internal.client;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.appsflyer.attribution.RequestError;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.C2097gc;
import com.google.android.gms.internal.ads.D7;
import com.google.android.gms.internal.ads.InterfaceC1696Gb;
import com.google.android.gms.internal.ads.InterfaceC1702Hb;
import com.google.android.gms.internal.ads.InterfaceC1866b6;
import com.google.android.gms.internal.ads.Z5;

/* loaded from: classes2.dex */
public abstract class J extends AbstractBinderC2814x5 implements K {
    public J() {
        super("com.google.android.gms.ads.internal.client.IAdManager");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        InterfaceC1622x c1620v = null;
        V u = null;
        A c1623y = null;
        InterfaceC1609n0 c1607m0 = null;
        InterfaceC1866b6 z5 = null;
        C2097gc c2097gc = null;
        T t = null;
        InterfaceC1619u c1618t = null;
        D7 d7 = null;
        P o = null;
        switch (i) {
            case 1:
                com.google.android.gms.dynamic.a aVarM = m();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, aVarM);
                return true;
            case 2:
                y();
                parcel2.writeNoException();
                return true;
            case 3:
                boolean zE0 = e0();
                parcel2.writeNoException();
                ClassLoader classLoader = AbstractC2857y5.a;
                parcel2.writeInt(zE0 ? 1 : 0);
                return true;
            case 4:
                zzm zzmVar = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                AbstractC2857y5.b(parcel);
                boolean zI2 = I2(zzmVar);
                parcel2.writeNoException();
                parcel2.writeInt(zI2 ? 1 : 0);
                return true;
            case 5:
                P();
                parcel2.writeNoException();
                return true;
            case 6:
                K();
                parcel2.writeNoException();
                return true;
            case 7:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdListener");
                    c1620v = iInterfaceQueryLocalInterface instanceof InterfaceC1622x ? (InterfaceC1622x) iInterfaceQueryLocalInterface : new C1620v(strongBinder);
                }
                AbstractC2857y5.b(parcel);
                N1(c1620v);
                parcel2.writeNoException();
                return true;
            case 8:
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.client.IAppEventListener");
                    o = iInterfaceQueryLocalInterface2 instanceof P ? (P) iInterfaceQueryLocalInterface2 : new O(strongBinder2);
                }
                AbstractC2857y5.b(parcel);
                A0(o);
                parcel2.writeNoException();
                return true;
            case 9:
                f1();
                parcel2.writeNoException();
                return true;
            case 10:
                parcel2.writeNoException();
                return true;
            case 11:
                j0();
                parcel2.writeNoException();
                return true;
            case 12:
                zzr zzrVarH = h();
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, zzrVarH);
                return true;
            case 13:
                zzr zzrVar = (zzr) AbstractC2857y5.a(parcel, zzr.CREATOR);
                AbstractC2857y5.b(parcel);
                A1(zzrVar);
                parcel2.writeNoException();
                return true;
            case 14:
                IBinder strongBinder3 = parcel.readStrongBinder();
                if (strongBinder3 != null) {
                    boolean z = strongBinder3.queryLocalInterface("com.google.android.gms.ads.internal.purchase.client.IInAppPurchaseListener") instanceof InterfaceC1696Gb;
                }
                AbstractC2857y5.b(parcel);
                H();
                parcel2.writeNoException();
                return true;
            case 15:
                IBinder strongBinder4 = parcel.readStrongBinder();
                if (strongBinder4 != null) {
                    boolean z2 = strongBinder4.queryLocalInterface("com.google.android.gms.ads.internal.purchase.client.IPlayStorePurchaseListener") instanceof InterfaceC1702Hb;
                }
                parcel.readString();
                AbstractC2857y5.b(parcel);
                g0();
                parcel2.writeNoException();
                return true;
            case 16:
            case 17:
            case 27:
            case 28:
            default:
                return false;
            case 18:
                String strZ = z();
                parcel2.writeNoException();
                parcel2.writeString(strZ);
                return true;
            case 19:
                IBinder strongBinder5 = parcel.readStrongBinder();
                if (strongBinder5 != null) {
                    IInterface iInterfaceQueryLocalInterface3 = strongBinder5.queryLocalInterface("com.google.android.gms.ads.internal.customrenderedad.client.IOnCustomRenderedAdLoadedListener");
                    d7 = iInterfaceQueryLocalInterface3 instanceof D7 ? (D7) iInterfaceQueryLocalInterface3 : new D7(strongBinder5, "com.google.android.gms.ads.internal.customrenderedad.client.IOnCustomRenderedAdLoadedListener", 0);
                }
                AbstractC2857y5.b(parcel);
                p1(d7);
                parcel2.writeNoException();
                return true;
            case 20:
                IBinder strongBinder6 = parcel.readStrongBinder();
                if (strongBinder6 != null) {
                    IInterface iInterfaceQueryLocalInterface4 = strongBinder6.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdClickListener");
                    c1618t = iInterfaceQueryLocalInterface4 instanceof InterfaceC1619u ? (InterfaceC1619u) iInterfaceQueryLocalInterface4 : new C1618t(strongBinder6, "com.google.android.gms.ads.internal.client.IAdClickListener", 0);
                }
                AbstractC2857y5.b(parcel);
                A3(c1618t);
                parcel2.writeNoException();
                return true;
            case 21:
                IBinder strongBinder7 = parcel.readStrongBinder();
                if (strongBinder7 != null) {
                    IInterface iInterfaceQueryLocalInterface5 = strongBinder7.queryLocalInterface("com.google.android.gms.ads.internal.client.ICorrelationIdProvider");
                    t = iInterfaceQueryLocalInterface5 instanceof T ? (T) iInterfaceQueryLocalInterface5 : new T(strongBinder7);
                }
                AbstractC2857y5.b(parcel);
                O1(t);
                parcel2.writeNoException();
                return true;
            case EventType.WINDOW_STATE /* 22 */:
                boolean zF = AbstractC2857y5.f(parcel);
                AbstractC2857y5.b(parcel);
                X3(zF);
                parcel2.writeNoException();
                return true;
            case EventType.AUDIO /* 23 */:
                boolean zF3 = F3();
                parcel2.writeNoException();
                ClassLoader classLoader2 = AbstractC2857y5.a;
                parcel2.writeInt(zF3 ? 1 : 0);
                return true;
            case EventType.VIDEO /* 24 */:
                IBinder strongBinder8 = parcel.readStrongBinder();
                if (strongBinder8 != null) {
                    IInterface iInterfaceQueryLocalInterface6 = strongBinder8.queryLocalInterface("com.google.android.gms.ads.internal.reward.client.IRewardedVideoAdListener");
                    c2097gc = iInterfaceQueryLocalInterface6 instanceof C2097gc ? (C2097gc) iInterfaceQueryLocalInterface6 : new C2097gc(strongBinder8);
                }
                AbstractC2857y5.b(parcel);
                E1(c2097gc);
                parcel2.writeNoException();
                return true;
            case EventType.SUBS /* 25 */:
                parcel.readString();
                AbstractC2857y5.b(parcel);
                b0();
                parcel2.writeNoException();
                return true;
            case EventType.CDN /* 26 */:
                v0 v0VarK = k();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, v0VarK);
                return true;
            case 29:
                zzfw zzfwVar = (zzfw) AbstractC2857y5.a(parcel, zzfw.CREATOR);
                AbstractC2857y5.b(parcel);
                W1(zzfwVar);
                parcel2.writeNoException();
                return true;
            case 30:
                AbstractC2857y5.b(parcel);
                Y();
                parcel2.writeNoException();
                return true;
            case 31:
                String strW = w();
                parcel2.writeNoException();
                parcel2.writeString(strW);
                return true;
            case 32:
                P pI = i();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, pI);
                return true;
            case 33:
                InterfaceC1622x interfaceC1622xZzi = zzi();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC1622xZzi);
                return true;
            case 34:
                boolean zF2 = AbstractC2857y5.f(parcel);
                AbstractC2857y5.b(parcel);
                c3(zF2);
                parcel2.writeNoException();
                return true;
            case 35:
                String strS = s();
                parcel2.writeNoException();
                parcel2.writeString(strS);
                return true;
            case 36:
                IBinder strongBinder9 = parcel.readStrongBinder();
                if (strongBinder9 != null) {
                    boolean z3 = strongBinder9.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdMetadataListener") instanceof M;
                }
                AbstractC2857y5.b(parcel);
                J();
                parcel2.writeNoException();
                return true;
            case 37:
                Bundle bundleJ = j();
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, bundleJ);
                return true;
            case 38:
                parcel.readString();
                AbstractC2857y5.b(parcel);
                i0();
                parcel2.writeNoException();
                return true;
            case 39:
                zzx zzxVar = (zzx) AbstractC2857y5.a(parcel, zzx.CREATOR);
                AbstractC2857y5.b(parcel);
                k1(zzxVar);
                parcel2.writeNoException();
                return true;
            case RequestError.NETWORK_FAILURE /* 40 */:
                IBinder strongBinder10 = parcel.readStrongBinder();
                if (strongBinder10 != null) {
                    IInterface iInterfaceQueryLocalInterface7 = strongBinder10.queryLocalInterface("com.google.android.gms.ads.internal.appopen.client.IAppOpenAdLoadCallback");
                    z5 = iInterfaceQueryLocalInterface7 instanceof InterfaceC1866b6 ? (InterfaceC1866b6) iInterfaceQueryLocalInterface7 : new Z5(strongBinder10, "com.google.android.gms.ads.internal.appopen.client.IAppOpenAdLoadCallback", 0);
                }
                AbstractC2857y5.b(parcel);
                g3(z5);
                parcel2.writeNoException();
                return true;
            case RequestError.NO_DEV_KEY /* 41 */:
                s0 s0VarN = n();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, s0VarN);
                return true;
            case 42:
                IBinder strongBinder11 = parcel.readStrongBinder();
                if (strongBinder11 != null) {
                    IInterface iInterfaceQueryLocalInterface8 = strongBinder11.queryLocalInterface("com.google.android.gms.ads.internal.client.IOnPaidEventListener");
                    c1607m0 = iInterfaceQueryLocalInterface8 instanceof InterfaceC1609n0 ? (InterfaceC1609n0) iInterfaceQueryLocalInterface8 : new C1607m0(strongBinder11);
                }
                AbstractC2857y5.b(parcel);
                j3(c1607m0);
                parcel2.writeNoException();
                return true;
            case 43:
                zzm zzmVar2 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                IBinder strongBinder12 = parcel.readStrongBinder();
                if (strongBinder12 != null) {
                    IInterface iInterfaceQueryLocalInterface9 = strongBinder12.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdLoadCallback");
                    c1623y = iInterfaceQueryLocalInterface9 instanceof A ? (A) iInterfaceQueryLocalInterface9 : new C1623y(strongBinder12, "com.google.android.gms.ads.internal.client.IAdLoadCallback", 0);
                }
                AbstractC2857y5.b(parcel);
                Y0(zzmVar2, c1623y);
                parcel2.writeNoException();
                return true;
            case 44:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                s1(aVarV3);
                parcel2.writeNoException();
                return true;
            case 45:
                IBinder strongBinder13 = parcel.readStrongBinder();
                if (strongBinder13 != null) {
                    IInterface iInterfaceQueryLocalInterface10 = strongBinder13.queryLocalInterface("com.google.android.gms.ads.internal.client.IFullScreenContentCallback");
                    u = iInterfaceQueryLocalInterface10 instanceof V ? (V) iInterfaceQueryLocalInterface10 : new U(strongBinder13, "com.google.android.gms.ads.internal.client.IFullScreenContentCallback", 0);
                }
                AbstractC2857y5.b(parcel);
                M0(u);
                parcel2.writeNoException();
                return true;
            case 46:
                boolean zT3 = t3();
                parcel2.writeNoException();
                ClassLoader classLoader3 = AbstractC2857y5.a;
                parcel2.writeInt(zT3 ? 1 : 0);
                return true;
        }
    }
}
