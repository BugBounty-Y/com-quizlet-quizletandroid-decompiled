package com.google.android.gms.ads.internal.client;

import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import com.google.android.gms.ads.formats.AdManagerAdViewOptions;
import com.google.android.gms.ads.formats.PublisherAdViewOptions;
import com.google.android.gms.internal.ads.AbstractBinderC2814x5;
import com.google.android.gms.internal.ads.AbstractC2857y5;
import com.google.android.gms.internal.ads.K8;
import com.google.android.gms.internal.ads.L8;
import com.google.android.gms.internal.ads.M8;
import com.google.android.gms.internal.ads.N8;
import com.google.android.gms.internal.ads.O8;
import com.google.android.gms.internal.ads.P8;
import com.google.android.gms.internal.ads.P9;
import com.google.android.gms.internal.ads.R8;
import com.google.android.gms.internal.ads.S8;
import com.google.android.gms.internal.ads.T8;
import com.google.android.gms.internal.ads.U8;
import com.google.android.gms.internal.ads.zzbfv;
import com.google.android.gms.internal.ads.zzbmg;

/* loaded from: classes2.dex */
public abstract class F extends AbstractBinderC2814x5 implements G {
    public F() {
        super("com.google.android.gms.ads.internal.client.IAdLoaderBuilder");
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        P8 o8;
        InterfaceC1622x c1620v = null;
        P9 p9 = null;
        U8 t8 = null;
        S8 r8 = null;
        T t = null;
        N8 m8 = null;
        L8 l8 = null;
        K8 k8 = null;
        switch (i) {
            case 1:
                D dZze = zze();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, dZze);
                return true;
            case 2:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.client.IAdListener");
                    c1620v = iInterfaceQueryLocalInterface instanceof InterfaceC1622x ? (InterfaceC1622x) iInterfaceQueryLocalInterface : new C1620v(strongBinder);
                }
                AbstractC2857y5.b(parcel);
                U2(c1620v);
                parcel2.writeNoException();
                return true;
            case 3:
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IOnAppInstallAdLoadedListener");
                    k8 = iInterfaceQueryLocalInterface2 instanceof K8 ? (K8) iInterfaceQueryLocalInterface2 : new K8(strongBinder2, "com.google.android.gms.ads.internal.formats.client.IOnAppInstallAdLoadedListener", 0);
                }
                AbstractC2857y5.b(parcel);
                K1(k8);
                parcel2.writeNoException();
                return true;
            case 4:
                IBinder strongBinder3 = parcel.readStrongBinder();
                if (strongBinder3 != null) {
                    IInterface iInterfaceQueryLocalInterface3 = strongBinder3.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IOnContentAdLoadedListener");
                    l8 = iInterfaceQueryLocalInterface3 instanceof L8 ? (L8) iInterfaceQueryLocalInterface3 : new L8(strongBinder3, "com.google.android.gms.ads.internal.formats.client.IOnContentAdLoadedListener", 0);
                }
                AbstractC2857y5.b(parcel);
                J0(l8);
                parcel2.writeNoException();
                return true;
            case 5:
                String string = parcel.readString();
                IBinder strongBinder4 = parcel.readStrongBinder();
                if (strongBinder4 == null) {
                    o8 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface4 = strongBinder4.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IOnCustomTemplateAdLoadedListener");
                    o8 = iInterfaceQueryLocalInterface4 instanceof P8 ? (P8) iInterfaceQueryLocalInterface4 : new O8(strongBinder4, "com.google.android.gms.ads.internal.formats.client.IOnCustomTemplateAdLoadedListener", 0);
                }
                IBinder strongBinder5 = parcel.readStrongBinder();
                if (strongBinder5 != null) {
                    IInterface iInterfaceQueryLocalInterface5 = strongBinder5.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IOnCustomClickListener");
                    m8 = iInterfaceQueryLocalInterface5 instanceof N8 ? (N8) iInterfaceQueryLocalInterface5 : new M8(strongBinder5, "com.google.android.gms.ads.internal.formats.client.IOnCustomClickListener", 0);
                }
                AbstractC2857y5.b(parcel);
                i3(string, o8, m8);
                parcel2.writeNoException();
                return true;
            case 6:
                zzbfv zzbfvVar = (zzbfv) AbstractC2857y5.a(parcel, zzbfv.CREATOR);
                AbstractC2857y5.b(parcel);
                J1(zzbfvVar);
                parcel2.writeNoException();
                return true;
            case 7:
                IBinder strongBinder6 = parcel.readStrongBinder();
                if (strongBinder6 != null) {
                    IInterface iInterfaceQueryLocalInterface6 = strongBinder6.queryLocalInterface("com.google.android.gms.ads.internal.client.ICorrelationIdProvider");
                    t = iInterfaceQueryLocalInterface6 instanceof T ? (T) iInterfaceQueryLocalInterface6 : new T(strongBinder6);
                }
                AbstractC2857y5.b(parcel);
                G3(t);
                parcel2.writeNoException();
                return true;
            case 8:
                IBinder strongBinder7 = parcel.readStrongBinder();
                if (strongBinder7 != null) {
                    IInterface iInterfaceQueryLocalInterface7 = strongBinder7.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IOnPublisherAdViewLoadedListener");
                    r8 = iInterfaceQueryLocalInterface7 instanceof S8 ? (S8) iInterfaceQueryLocalInterface7 : new R8(strongBinder7, "com.google.android.gms.ads.internal.formats.client.IOnPublisherAdViewLoadedListener", 0);
                }
                zzr zzrVar = (zzr) AbstractC2857y5.a(parcel, zzr.CREATOR);
                AbstractC2857y5.b(parcel);
                m3(r8, zzrVar);
                parcel2.writeNoException();
                return true;
            case 9:
                PublisherAdViewOptions publisherAdViewOptions = (PublisherAdViewOptions) AbstractC2857y5.a(parcel, PublisherAdViewOptions.CREATOR);
                AbstractC2857y5.b(parcel);
                P3(publisherAdViewOptions);
                parcel2.writeNoException();
                return true;
            case 10:
                IBinder strongBinder8 = parcel.readStrongBinder();
                if (strongBinder8 != null) {
                    IInterface iInterfaceQueryLocalInterface8 = strongBinder8.queryLocalInterface("com.google.android.gms.ads.internal.formats.client.IOnUnifiedNativeAdLoadedListener");
                    t8 = iInterfaceQueryLocalInterface8 instanceof U8 ? (U8) iInterfaceQueryLocalInterface8 : new T8(strongBinder8, "com.google.android.gms.ads.internal.formats.client.IOnUnifiedNativeAdLoadedListener", 0);
                }
                AbstractC2857y5.b(parcel);
                o3(t8);
                parcel2.writeNoException();
                return true;
            case 11:
            case 12:
            default:
                return false;
            case 13:
                zzbmg zzbmgVar = (zzbmg) AbstractC2857y5.a(parcel, zzbmg.CREATOR);
                AbstractC2857y5.b(parcel);
                O3(zzbmgVar);
                parcel2.writeNoException();
                return true;
            case 14:
                IBinder strongBinder9 = parcel.readStrongBinder();
                if (strongBinder9 != null) {
                    IInterface iInterfaceQueryLocalInterface9 = strongBinder9.queryLocalInterface("com.google.android.gms.ads.internal.instream.client.IInstreamAdLoadCallback");
                    p9 = iInterfaceQueryLocalInterface9 instanceof P9 ? (P9) iInterfaceQueryLocalInterface9 : new P9(strongBinder9, "com.google.android.gms.ads.internal.instream.client.IInstreamAdLoadCallback", 0);
                }
                AbstractC2857y5.b(parcel);
                W2(p9);
                parcel2.writeNoException();
                return true;
            case 15:
                AdManagerAdViewOptions adManagerAdViewOptions = (AdManagerAdViewOptions) AbstractC2857y5.a(parcel, AdManagerAdViewOptions.CREATOR);
                AbstractC2857y5.b(parcel);
                S3(adManagerAdViewOptions);
                parcel2.writeNoException();
                return true;
        }
    }
}
