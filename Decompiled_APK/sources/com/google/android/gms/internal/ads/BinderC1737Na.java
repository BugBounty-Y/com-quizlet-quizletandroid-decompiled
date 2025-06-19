package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.text.TextUtils;
import com.comscore.streaming.EventType;
import com.google.ads.mediation.AbstractAdViewAdapter;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.mediation.MediationBannerAdapter;
import com.google.android.gms.ads.mediation.MediationInterstitialAdapter;
import com.google.android.gms.ads.mediation.MediationNativeAdapter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Na, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC1737Na extends AbstractBinderC2814x5 implements InterfaceC2911za {
    public final Object a;
    public C2326lq b;
    public InterfaceC2226jc c;
    public com.google.android.gms.dynamic.a d;

    public BinderC1737Na() {
        super("com.google.android.gms.ads.internal.mediation.client.IMediationAdapter");
    }

    public static final boolean h4(zzm zzmVar) {
        if (zzmVar.f) {
            return true;
        }
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        return com.google.android.gms.ads.internal.util.client.c.l();
    }

    public static final String i4(zzm zzmVar, String str) {
        String str2 = zzmVar.u;
        try {
            return new JSONObject(str).getString("max_ad_content_rating");
        } catch (JSONException unused) {
            return str2;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void E2(zzm zzmVar, String str) throws RemoteException {
        e4(zzmVar, str);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final boolean H() {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void J2(boolean z) {
        Object obj = this.a;
        if (obj instanceof AbstractAdViewAdapter) {
            try {
                ((AbstractAdViewAdapter) obj).onImmersiveModeUpdated(z);
                return;
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.util.client.i.f("", th);
                return;
            }
        }
        com.google.android.gms.ads.internal.util.client.i.d(AbstractAdViewAdapter.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final boolean L() throws RemoteException {
        Object obj = this.a;
        if ((obj instanceof com.google.android.gms.ads.mediation.a) || Objects.equals(obj.getClass().getCanonicalName(), "com.google.ads.mediation.admob.AdMobAdapter")) {
            return this.c != null;
        }
        com.google.android.gms.ads.internal.util.client.i.h(com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
        throw new RemoteException();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void N() throws RemoteException {
        Object obj = this.a;
        if (obj instanceof com.google.android.gms.ads.mediation.e) {
            try {
                ((com.google.android.gms.ads.mediation.e) obj).onResume();
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.util.client.i.f("", th);
                throw new RemoteException();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final C1683Ea O() {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void Q() throws RemoteException {
        Object obj = this.a;
        if (obj instanceof com.google.android.gms.ads.mediation.a) {
            com.google.android.gms.ads.internal.util.client.i.e("Can not show null mediated rewarded ad.");
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.i.h(com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
        throw new RemoteException();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void U0() throws RemoteException {
        Object obj = this.a;
        if (obj instanceof com.google.android.gms.ads.mediation.e) {
            try {
                ((com.google.android.gms.ads.mediation.e) obj).onPause();
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.util.client.i.f("", th);
                throw new RemoteException();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void U3(com.google.android.gms.dynamic.a aVar) throws RemoteException {
        Object obj = this.a;
        if ((obj instanceof com.google.android.gms.ads.mediation.a) || (obj instanceof MediationInterstitialAdapter)) {
            if (obj instanceof MediationInterstitialAdapter) {
                h0();
                return;
            } else {
                com.google.android.gms.ads.internal.util.client.i.d("Show interstitial ad from adapter.");
                com.google.android.gms.ads.internal.util.client.i.e("Can not show null mediation interstitial ad.");
                throw new RemoteException();
            }
        }
        com.google.android.gms.ads.internal.util.client.i.h(MediationInterstitialAdapter.class.getCanonicalName() + " or " + com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
        throw new RemoteException();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void W3(com.google.android.gms.dynamic.a aVar, zzm zzmVar, String str, String str2, InterfaceC1671Ca interfaceC1671Ca, zzbfv zzbfvVar, ArrayList arrayList) throws RemoteException {
        Object obj = this.a;
        boolean z = obj instanceof MediationNativeAdapter;
        if (!z && !(obj instanceof com.google.android.gms.ads.mediation.a)) {
            com.google.android.gms.ads.internal.util.client.i.h(MediationNativeAdapter.class.getCanonicalName() + " or " + com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.i.d("Requesting native ad from adapter.");
        if (z) {
            try {
                MediationNativeAdapter mediationNativeAdapter = (MediationNativeAdapter) obj;
                List list = zzmVar.e;
                HashSet hashSet = list != null ? new HashSet(list) : null;
                long j = zzmVar.b;
                if (j != -1) {
                    new Date(j);
                }
                boolean zH4 = h4(zzmVar);
                int i = zzmVar.g;
                boolean z2 = zzmVar.r;
                i4(zzmVar, str);
                C1749Pa c1749Pa = new C1749Pa(hashSet, zH4, i, zzbfvVar, arrayList, z2);
                Bundle bundle = zzmVar.m;
                Bundle bundle2 = bundle != null ? bundle.getBundle(mediationNativeAdapter.getClass().getName()) : null;
                this.b = new C2326lq(interfaceC1671Ca);
                mediationNativeAdapter.requestNativeAd((Context) com.google.android.gms.dynamic.b.I3(aVar), this.b, g4(str, zzmVar, str2), c1749Pa, bundle2);
                return;
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.util.client.i.f("", th);
                LA.j(aVar, th, "adapter.requestNativeAd");
                throw new RemoteException();
            }
        }
        if (obj instanceof com.google.android.gms.ads.mediation.a) {
            try {
                C1731Ma c1731Ma = new C1731Ma(this, interfaceC1671Ca, 1);
                g4(str, zzmVar, str2);
                f4(zzmVar);
                h4(zzmVar);
                i4(zzmVar, str);
                ((com.google.android.gms.ads.mediation.a) obj).loadNativeAdMapper(new com.google.android.gms.ads.mediation.k(), c1731Ma);
            } catch (Throwable th2) {
                com.google.android.gms.ads.internal.util.client.i.f("", th2);
                LA.j(aVar, th2, "adapter.loadNativeAdMapper");
                String message = th2.getMessage();
                if (TextUtils.isEmpty(message) || !message.equals("Method is not found")) {
                    throw new RemoteException();
                }
                try {
                    C1725La c1725La = new C1725La(this, interfaceC1671Ca, 1);
                    g4(str, zzmVar, str2);
                    f4(zzmVar);
                    h4(zzmVar);
                    i4(zzmVar, str);
                    ((com.google.android.gms.ads.mediation.a) obj).loadNativeAd(new com.google.android.gms.ads.mediation.k(), c1725La);
                } catch (Throwable th3) {
                    com.google.android.gms.ads.internal.util.client.i.f("", th3);
                    LA.j(aVar, th3, "adapter.loadNativeAd");
                    throw new RemoteException();
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void Z0(com.google.android.gms.dynamic.a aVar, com.google.android.gms.ads.internal.client.zzr zzrVar, zzm zzmVar, String str, String str2, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        com.google.android.gms.ads.h hVar;
        Object obj = this.a;
        boolean z = obj instanceof MediationBannerAdapter;
        if (!z && !(obj instanceof com.google.android.gms.ads.mediation.a)) {
            com.google.android.gms.ads.internal.util.client.i.h(MediationBannerAdapter.class.getCanonicalName() + " or " + com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.i.d("Requesting banner ad from adapter.");
        boolean z2 = zzrVar.n;
        int i = zzrVar.b;
        int i2 = zzrVar.e;
        if (z2) {
            com.google.android.gms.ads.h hVar2 = new com.google.android.gms.ads.h(i2, i);
            hVar2.e = true;
            hVar2.f = i;
            hVar = hVar2;
        } else {
            hVar = new com.google.android.gms.ads.h(i2, i, zzrVar.a);
        }
        if (!z) {
            if (obj instanceof com.google.android.gms.ads.mediation.a) {
                try {
                    C1725La c1725La = new C1725La(this, interfaceC1671Ca, 0);
                    g4(str, zzmVar, str2);
                    f4(zzmVar);
                    h4(zzmVar);
                    i4(zzmVar, str);
                    ((com.google.android.gms.ads.mediation.a) obj).loadBannerAd(new com.google.android.gms.ads.mediation.g(), c1725La);
                    return;
                } catch (Throwable th) {
                    com.google.android.gms.ads.internal.util.client.i.f("", th);
                    LA.j(aVar, th, "adapter.loadBannerAd");
                    throw new RemoteException();
                }
            }
            return;
        }
        try {
            MediationBannerAdapter mediationBannerAdapter = (MediationBannerAdapter) obj;
            List list = zzmVar.e;
            HashSet hashSet = list != null ? new HashSet(list) : null;
            long j = zzmVar.b;
            if (j != -1) {
                new Date(j);
            }
            boolean zH4 = h4(zzmVar);
            int i3 = zzmVar.g;
            boolean z3 = zzmVar.r;
            i4(zzmVar, str);
            C1719Ka c1719Ka = new C1719Ka(hashSet, zH4, i3, z3);
            Bundle bundle = zzmVar.m;
            mediationBannerAdapter.requestBannerAd((Context) com.google.android.gms.dynamic.b.I3(aVar), new C2326lq(interfaceC1671Ca), g4(str, zzmVar, str2), hVar, c1719Ka, bundle != null ? bundle.getBundle(mediationBannerAdapter.getClass().getName()) : null);
        } catch (Throwable th2) {
            com.google.android.gms.ads.internal.util.client.i.f("", th2);
            LA.j(aVar, th2, "adapter.requestBannerAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void c4(com.google.android.gms.dynamic.a aVar, zzm zzmVar, String str, String str2, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        Object obj = this.a;
        boolean z = obj instanceof MediationInterstitialAdapter;
        if (!z && !(obj instanceof com.google.android.gms.ads.mediation.a)) {
            com.google.android.gms.ads.internal.util.client.i.h(MediationInterstitialAdapter.class.getCanonicalName() + " or " + com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.i.d("Requesting interstitial ad from adapter.");
        if (!z) {
            if (obj instanceof com.google.android.gms.ads.mediation.a) {
                try {
                    C1731Ma c1731Ma = new C1731Ma(this, interfaceC1671Ca, 0);
                    g4(str, zzmVar, str2);
                    f4(zzmVar);
                    h4(zzmVar);
                    i4(zzmVar, str);
                    ((com.google.android.gms.ads.mediation.a) obj).loadInterstitialAd(new com.google.android.gms.ads.mediation.i(), c1731Ma);
                    return;
                } catch (Throwable th) {
                    com.google.android.gms.ads.internal.util.client.i.f("", th);
                    LA.j(aVar, th, "adapter.loadInterstitialAd");
                    throw new RemoteException();
                }
            }
            return;
        }
        try {
            MediationInterstitialAdapter mediationInterstitialAdapter = (MediationInterstitialAdapter) obj;
            List list = zzmVar.e;
            HashSet hashSet = list != null ? new HashSet(list) : null;
            long j = zzmVar.b;
            if (j != -1) {
                new Date(j);
            }
            boolean zH4 = h4(zzmVar);
            int i = zzmVar.g;
            boolean z2 = zzmVar.r;
            i4(zzmVar, str);
            C1719Ka c1719Ka = new C1719Ka(hashSet, zH4, i, z2);
            Bundle bundle = zzmVar.m;
            mediationInterstitialAdapter.requestInterstitialAd((Context) com.google.android.gms.dynamic.b.I3(aVar), new C2326lq(interfaceC1671Ca), g4(str, zzmVar, str2), c1719Ka, bundle != null ? bundle.getBundle(mediationInterstitialAdapter.getClass().getName()) : null);
        } catch (Throwable th2) {
            com.google.android.gms.ads.internal.util.client.i.f("", th2);
            LA.j(aVar, th2, "adapter.requestInterstitialAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final C1689Fa d0() {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void d2(com.google.android.gms.dynamic.a aVar, zzm zzmVar, String str, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        Object obj = this.a;
        if (!(obj instanceof com.google.android.gms.ads.mediation.a)) {
            com.google.android.gms.ads.internal.util.client.i.h(com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.i.d("Requesting rewarded ad from adapter.");
        try {
            C1725La c1725La = new C1725La(this, interfaceC1671Ca, 2);
            g4(str, zzmVar, null);
            f4(zzmVar);
            h4(zzmVar);
            i4(zzmVar, str);
            ((com.google.android.gms.ads.mediation.a) obj).loadRewardedAd(new com.google.android.gms.ads.mediation.m(), c1725La);
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            LA.j(aVar, e, "adapter.loadRewardedAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void d3(com.google.android.gms.dynamic.a aVar, InterfaceC2226jc interfaceC2226jc, List list) throws RemoteException {
        com.google.android.gms.ads.internal.util.client.i.h("Could not initialize rewarded video adapter.");
        throw new RemoteException();
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) throws RemoteException {
        InterfaceC1671Ca c1659Aa;
        InterfaceC1671Ca c1659Aa2;
        InterfaceC1671Ca c1659Aa3;
        InterfaceC1671Ca c1659Aa4;
        InterfaceC2226jc c2141hc;
        InterfaceC1671Ca c1659Aa5;
        InterfaceC2226jc c2141hc2;
        Os os;
        InterfaceC1671Ca c1659Aa6;
        H9 g9;
        InterfaceC1671Ca c1659Aa7;
        InterfaceC1671Ca c1659Aa8;
        InterfaceC1671Ca c1659Aa9 = null;
        switch (i) {
            case 1:
                com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.ads.internal.client.zzr zzrVar = (com.google.android.gms.ads.internal.client.zzr) AbstractC2857y5.a(parcel, com.google.android.gms.ads.internal.client.zzr.CREATOR);
                zzm zzmVar = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string = parcel.readString();
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder == null) {
                    c1659Aa = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
                    c1659Aa = iInterfaceQueryLocalInterface instanceof InterfaceC1671Ca ? (InterfaceC1671Ca) iInterfaceQueryLocalInterface : new C1659Aa(strongBinder);
                }
                AbstractC2857y5.b(parcel);
                Z0(aVarV3, zzrVar, zzmVar, string, null, c1659Aa);
                parcel2.writeNoException();
                return true;
            case 2:
                com.google.android.gms.dynamic.a aVarM = m();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, aVarM);
                return true;
            case 3:
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzm zzmVar2 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string2 = parcel.readString();
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 == null) {
                    c1659Aa2 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
                    c1659Aa2 = iInterfaceQueryLocalInterface2 instanceof InterfaceC1671Ca ? (InterfaceC1671Ca) iInterfaceQueryLocalInterface2 : new C1659Aa(strongBinder2);
                }
                AbstractC2857y5.b(parcel);
                c4(aVarV32, zzmVar2, string2, null, c1659Aa2);
                parcel2.writeNoException();
                return true;
            case 4:
                h0();
                parcel2.writeNoException();
                return true;
            case 5:
                v();
                parcel2.writeNoException();
                return true;
            case 6:
                com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.ads.internal.client.zzr zzrVar2 = (com.google.android.gms.ads.internal.client.zzr) AbstractC2857y5.a(parcel, com.google.android.gms.ads.internal.client.zzr.CREATOR);
                zzm zzmVar3 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string3 = parcel.readString();
                String string4 = parcel.readString();
                IBinder strongBinder3 = parcel.readStrongBinder();
                if (strongBinder3 == null) {
                    c1659Aa3 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface3 = strongBinder3.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
                    c1659Aa3 = iInterfaceQueryLocalInterface3 instanceof InterfaceC1671Ca ? (InterfaceC1671Ca) iInterfaceQueryLocalInterface3 : new C1659Aa(strongBinder3);
                }
                AbstractC2857y5.b(parcel);
                Z0(aVarV33, zzrVar2, zzmVar3, string3, string4, c1659Aa3);
                parcel2.writeNoException();
                return true;
            case 7:
                com.google.android.gms.dynamic.a aVarV34 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzm zzmVar4 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string5 = parcel.readString();
                String string6 = parcel.readString();
                IBinder strongBinder4 = parcel.readStrongBinder();
                if (strongBinder4 == null) {
                    c1659Aa4 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface4 = strongBinder4.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
                    c1659Aa4 = iInterfaceQueryLocalInterface4 instanceof InterfaceC1671Ca ? (InterfaceC1671Ca) iInterfaceQueryLocalInterface4 : new C1659Aa(strongBinder4);
                }
                AbstractC2857y5.b(parcel);
                c4(aVarV34, zzmVar4, string5, string6, c1659Aa4);
                parcel2.writeNoException();
                return true;
            case 8:
                U0();
                parcel2.writeNoException();
                return true;
            case 9:
                N();
                parcel2.writeNoException();
                return true;
            case 10:
                com.google.android.gms.dynamic.a aVarV35 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzm zzmVar5 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                parcel.readString();
                IBinder strongBinder5 = parcel.readStrongBinder();
                if (strongBinder5 == null) {
                    c2141hc = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface5 = strongBinder5.queryLocalInterface("com.google.android.gms.ads.internal.reward.mediation.client.IMediationRewardedVideoAdListener");
                    c2141hc = iInterfaceQueryLocalInterface5 instanceof InterfaceC2226jc ? (InterfaceC2226jc) iInterfaceQueryLocalInterface5 : new C2141hc(strongBinder5, "com.google.android.gms.ads.internal.reward.mediation.client.IMediationRewardedVideoAdListener", 0);
                }
                String string7 = parcel.readString();
                AbstractC2857y5.b(parcel);
                z3(aVarV35, zzmVar5, c2141hc, string7);
                parcel2.writeNoException();
                return true;
            case 11:
                zzm zzmVar6 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string8 = parcel.readString();
                AbstractC2857y5.b(parcel);
                e4(zzmVar6, string8);
                parcel2.writeNoException();
                return true;
            case 12:
                Q();
                throw null;
            case 13:
                boolean zL = L();
                parcel2.writeNoException();
                ClassLoader classLoader = AbstractC2857y5.a;
                parcel2.writeInt(zL ? 1 : 0);
                return true;
            case 14:
                com.google.android.gms.dynamic.a aVarV36 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzm zzmVar7 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string9 = parcel.readString();
                String string10 = parcel.readString();
                IBinder strongBinder6 = parcel.readStrongBinder();
                if (strongBinder6 == null) {
                    c1659Aa5 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface6 = strongBinder6.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
                    c1659Aa5 = iInterfaceQueryLocalInterface6 instanceof InterfaceC1671Ca ? (InterfaceC1671Ca) iInterfaceQueryLocalInterface6 : new C1659Aa(strongBinder6);
                }
                zzbfv zzbfvVar = (zzbfv) AbstractC2857y5.a(parcel, zzbfv.CREATOR);
                ArrayList<String> arrayListCreateStringArrayList = parcel.createStringArrayList();
                AbstractC2857y5.b(parcel);
                W3(aVarV36, zzmVar7, string9, string10, c1659Aa5, zzbfvVar, arrayListCreateStringArrayList);
                parcel2.writeNoException();
                return true;
            case 15:
                parcel2.writeNoException();
                ClassLoader classLoader2 = AbstractC2857y5.a;
                parcel2.writeStrongBinder(null);
                return true;
            case 16:
                parcel2.writeNoException();
                ClassLoader classLoader3 = AbstractC2857y5.a;
                parcel2.writeStrongBinder(null);
                return true;
            case 17:
                Bundle bundle = new Bundle();
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, bundle);
                return true;
            case 18:
                Bundle bundle2 = new Bundle();
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, bundle2);
                return true;
            case 19:
                Bundle bundle3 = new Bundle();
                parcel2.writeNoException();
                AbstractC2857y5.d(parcel2, bundle3);
                return true;
            case 20:
                zzm zzmVar8 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string11 = parcel.readString();
                parcel.readString();
                AbstractC2857y5.b(parcel);
                e4(zzmVar8, string11);
                parcel2.writeNoException();
                return true;
            case 21:
                com.google.android.gms.dynamic.a aVarV37 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                n0(aVarV37);
                parcel2.writeNoException();
                return true;
            case EventType.WINDOW_STATE /* 22 */:
                parcel2.writeNoException();
                ClassLoader classLoader4 = AbstractC2857y5.a;
                parcel2.writeInt(0);
                return true;
            case EventType.AUDIO /* 23 */:
                com.google.android.gms.dynamic.a aVarV38 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder7 = parcel.readStrongBinder();
                if (strongBinder7 != null) {
                    IInterface iInterfaceQueryLocalInterface7 = strongBinder7.queryLocalInterface("com.google.android.gms.ads.internal.reward.mediation.client.IMediationRewardedVideoAdListener");
                    c2141hc2 = iInterfaceQueryLocalInterface7 instanceof InterfaceC2226jc ? (InterfaceC2226jc) iInterfaceQueryLocalInterface7 : new C2141hc(strongBinder7, "com.google.android.gms.ads.internal.reward.mediation.client.IMediationRewardedVideoAdListener", 0);
                } else {
                    c2141hc2 = null;
                }
                ArrayList<String> arrayListCreateStringArrayList2 = parcel.createStringArrayList();
                AbstractC2857y5.b(parcel);
                d3(aVarV38, c2141hc2, arrayListCreateStringArrayList2);
                throw null;
            case EventType.VIDEO /* 24 */:
                C2326lq c2326lq = this.b;
                J8 j8 = (c2326lq == null || (os = (Os) c2326lq.d) == null) ? null : (J8) os.b;
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, j8);
                return true;
            case EventType.SUBS /* 25 */:
                boolean zF = AbstractC2857y5.f(parcel);
                AbstractC2857y5.b(parcel);
                J2(zF);
                parcel2.writeNoException();
                return true;
            case EventType.CDN /* 26 */:
                com.google.android.gms.ads.internal.client.v0 v0VarG = g();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, v0VarG);
                return true;
            case 27:
                InterfaceC1707Ia interfaceC1707IaN = n();
                parcel2.writeNoException();
                AbstractC2857y5.e(parcel2, interfaceC1707IaN);
                return true;
            case 28:
                com.google.android.gms.dynamic.a aVarV39 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzm zzmVar9 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string12 = parcel.readString();
                IBinder strongBinder8 = parcel.readStrongBinder();
                if (strongBinder8 == null) {
                    c1659Aa6 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface8 = strongBinder8.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
                    c1659Aa6 = iInterfaceQueryLocalInterface8 instanceof InterfaceC1671Ca ? (InterfaceC1671Ca) iInterfaceQueryLocalInterface8 : new C1659Aa(strongBinder8);
                }
                AbstractC2857y5.b(parcel);
                d2(aVarV39, zzmVar9, string12, c1659Aa6);
                parcel2.writeNoException();
                return true;
            case 29:
            default:
                return false;
            case 30:
                com.google.android.gms.dynamic.a aVarV310 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                n3(aVarV310);
                throw null;
            case 31:
                com.google.android.gms.dynamic.a aVarV311 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder9 = parcel.readStrongBinder();
                if (strongBinder9 == null) {
                    g9 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface9 = strongBinder9.queryLocalInterface("com.google.android.gms.ads.internal.initialization.IAdapterInitializationCallback");
                    g9 = iInterfaceQueryLocalInterface9 instanceof H9 ? (H9) iInterfaceQueryLocalInterface9 : new G9(strongBinder9, "com.google.android.gms.ads.internal.initialization.IAdapterInitializationCallback", 0);
                }
                ArrayList arrayListCreateTypedArrayList = parcel.createTypedArrayList(zzbme.CREATOR);
                AbstractC2857y5.b(parcel);
                s0(aVarV311, g9, arrayListCreateTypedArrayList);
                parcel2.writeNoException();
                return true;
            case 32:
                com.google.android.gms.dynamic.a aVarV312 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzm zzmVar10 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string13 = parcel.readString();
                IBinder strongBinder10 = parcel.readStrongBinder();
                if (strongBinder10 == null) {
                    c1659Aa7 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface10 = strongBinder10.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
                    c1659Aa7 = iInterfaceQueryLocalInterface10 instanceof InterfaceC1671Ca ? (InterfaceC1671Ca) iInterfaceQueryLocalInterface10 : new C1659Aa(strongBinder10);
                }
                AbstractC2857y5.b(parcel);
                n1(aVarV312, zzmVar10, string13, c1659Aa7);
                parcel2.writeNoException();
                return true;
            case 33:
                k();
                parcel2.writeNoException();
                ClassLoader classLoader5 = AbstractC2857y5.a;
                parcel2.writeInt(0);
                return true;
            case 34:
                l();
                parcel2.writeNoException();
                ClassLoader classLoader6 = AbstractC2857y5.a;
                parcel2.writeInt(0);
                return true;
            case 35:
                com.google.android.gms.dynamic.a aVarV313 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                com.google.android.gms.ads.internal.client.zzr zzrVar3 = (com.google.android.gms.ads.internal.client.zzr) AbstractC2857y5.a(parcel, com.google.android.gms.ads.internal.client.zzr.CREATOR);
                zzm zzmVar11 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string14 = parcel.readString();
                String string15 = parcel.readString();
                IBinder strongBinder11 = parcel.readStrongBinder();
                if (strongBinder11 == null) {
                    c1659Aa8 = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface11 = strongBinder11.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
                    c1659Aa8 = iInterfaceQueryLocalInterface11 instanceof InterfaceC1671Ca ? (InterfaceC1671Ca) iInterfaceQueryLocalInterface11 : new C1659Aa(strongBinder11);
                }
                AbstractC2857y5.b(parcel);
                x0(aVarV313, zzrVar3, zzmVar11, string14, string15, c1659Aa8);
                parcel2.writeNoException();
                return true;
            case 36:
                parcel2.writeNoException();
                ClassLoader classLoader7 = AbstractC2857y5.a;
                parcel2.writeStrongBinder(null);
                return true;
            case 37:
                com.google.android.gms.dynamic.a aVarV314 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                U3(aVarV314);
                parcel2.writeNoException();
                return true;
            case 38:
                com.google.android.gms.dynamic.a aVarV315 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                zzm zzmVar12 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                String string16 = parcel.readString();
                IBinder strongBinder12 = parcel.readStrongBinder();
                if (strongBinder12 != null) {
                    IInterface iInterfaceQueryLocalInterface12 = strongBinder12.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.IMediationAdapterListener");
                    c1659Aa9 = iInterfaceQueryLocalInterface12 instanceof InterfaceC1671Ca ? (InterfaceC1671Ca) iInterfaceQueryLocalInterface12 : new C1659Aa(strongBinder12);
                }
                AbstractC2857y5.b(parcel);
                n2(aVarV315, zzmVar12, string16, c1659Aa9);
                parcel2.writeNoException();
                return true;
            case 39:
                com.google.android.gms.dynamic.a aVarV316 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                k2(aVarV316);
                throw null;
        }
    }

    public final void e4(zzm zzmVar, String str) throws RemoteException {
        Object obj = this.a;
        if (obj instanceof com.google.android.gms.ads.mediation.a) {
            d2(this.d, zzmVar, str, new BinderC1743Oa((com.google.android.gms.ads.mediation.a) obj, this.c));
            return;
        }
        com.google.android.gms.ads.internal.util.client.i.h(com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
        throw new RemoteException();
    }

    public final void f4(zzm zzmVar) {
        Bundle bundle = zzmVar.m;
        if (bundle == null || bundle.getBundle(this.a.getClass().getName()) == null) {
            new Bundle();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final com.google.android.gms.ads.internal.client.v0 g() {
        Object obj = this.a;
        if (obj instanceof AbstractAdViewAdapter) {
            try {
                return ((AbstractAdViewAdapter) obj).getVideoController();
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.util.client.i.f("", th);
            }
        }
        return null;
    }

    public final Bundle g4(String str, zzm zzmVar, String str2) throws RemoteException {
        com.google.android.gms.ads.internal.util.client.i.d("Server parameters: ".concat(String.valueOf(str)));
        try {
            Bundle bundle = new Bundle();
            if (str != null) {
                JSONObject jSONObject = new JSONObject(str);
                Bundle bundle2 = new Bundle();
                Iterator<String> itKeys = jSONObject.keys();
                while (itKeys.hasNext()) {
                    String next = itKeys.next();
                    bundle2.putString(next, jSONObject.getString(next));
                }
                bundle = bundle2;
            }
            if (this.a instanceof AdMobAdapter) {
                bundle.putString("adJson", str2);
                if (zzmVar != null) {
                    bundle.putInt("tagForChildDirectedTreatment", zzmVar.g);
                }
            }
            bundle.remove("max_ad_content_rating");
            return bundle;
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void h0() throws RemoteException {
        Object obj = this.a;
        if (obj instanceof MediationInterstitialAdapter) {
            com.google.android.gms.ads.internal.util.client.i.d("Showing interstitial from adapter.");
            try {
                ((MediationInterstitialAdapter) obj).showInterstitial();
                return;
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.util.client.i.f("", th);
                throw new RemoteException();
            }
        }
        com.google.android.gms.ads.internal.util.client.i.h(MediationInterstitialAdapter.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
        throw new RemoteException();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final C1677Da i() {
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final zzbrz k() {
        Object obj = this.a;
        if (!(obj instanceof com.google.android.gms.ads.mediation.a)) {
            return null;
        }
        ((com.google.android.gms.ads.mediation.a) obj).getVersionInfo();
        throw null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void k2(com.google.android.gms.dynamic.a aVar) throws RemoteException {
        Object obj = this.a;
        if (obj instanceof com.google.android.gms.ads.mediation.a) {
            com.google.android.gms.ads.internal.util.client.i.d("Show app open ad from adapter.");
            com.google.android.gms.ads.internal.util.client.i.e("Can not show null mediation app open ad.");
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.i.h(com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
        throw new RemoteException();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final zzbrz l() {
        Object obj = this.a;
        if (!(obj instanceof com.google.android.gms.ads.mediation.a)) {
            return null;
        }
        ((com.google.android.gms.ads.mediation.a) obj).getSDKVersionInfo();
        throw null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final com.google.android.gms.dynamic.a m() throws RemoteException {
        Object obj = this.a;
        if (obj instanceof MediationBannerAdapter) {
            try {
                return new com.google.android.gms.dynamic.b(((MediationBannerAdapter) obj).getBannerView());
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.util.client.i.f("", th);
                throw new RemoteException();
            }
        }
        if (obj instanceof com.google.android.gms.ads.mediation.a) {
            return new com.google.android.gms.dynamic.b(null);
        }
        com.google.android.gms.ads.internal.util.client.i.h(MediationBannerAdapter.class.getCanonicalName() + " or " + com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
        throw new RemoteException();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final InterfaceC1707Ia n() {
        com.google.ads.mediation.a aVar;
        Object obj = this.a;
        if (!(obj instanceof MediationNativeAdapter)) {
            boolean z = obj instanceof com.google.android.gms.ads.mediation.a;
            return null;
        }
        C2326lq c2326lq = this.b;
        if (c2326lq == null || (aVar = (com.google.ads.mediation.a) c2326lq.c) == null) {
            return null;
        }
        return new BinderC1755Qa(aVar);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void n0(com.google.android.gms.dynamic.a aVar) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void n1(com.google.android.gms.dynamic.a aVar, zzm zzmVar, String str, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        Object obj = this.a;
        if (!(obj instanceof com.google.android.gms.ads.mediation.a)) {
            com.google.android.gms.ads.internal.util.client.i.h(com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.i.d("Requesting rewarded interstitial ad from adapter.");
        try {
            C1725La c1725La = new C1725La(this, interfaceC1671Ca, 2);
            g4(str, zzmVar, null);
            f4(zzmVar);
            h4(zzmVar);
            i4(zzmVar, str);
            ((com.google.android.gms.ads.mediation.a) obj).loadRewardedInterstitialAd(new com.google.android.gms.ads.mediation.m(), c1725La);
        } catch (Exception e) {
            LA.j(aVar, e, "adapter.loadRewardedInterstitialAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void n2(com.google.android.gms.dynamic.a aVar, zzm zzmVar, String str, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        Object obj = this.a;
        if (!(obj instanceof com.google.android.gms.ads.mediation.a)) {
            com.google.android.gms.ads.internal.util.client.i.h(com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.i.d("Requesting app open ad from adapter.");
        try {
            C1731Ma c1731Ma = new C1731Ma(this, interfaceC1671Ca, 2);
            g4(str, zzmVar, null);
            f4(zzmVar);
            h4(zzmVar);
            i4(zzmVar, str);
            ((com.google.android.gms.ads.mediation.a) obj).loadAppOpenAd(new com.google.android.gms.ads.mediation.f(), c1731Ma);
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            LA.j(aVar, e, "adapter.loadAppOpenAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void n3(com.google.android.gms.dynamic.a aVar) throws RemoteException {
        Object obj = this.a;
        if (obj instanceof com.google.android.gms.ads.mediation.a) {
            com.google.android.gms.ads.internal.util.client.i.d("Show rewarded ad from adapter.");
            com.google.android.gms.ads.internal.util.client.i.e("Can not show null mediation rewarded ad.");
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.i.h(com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
        throw new RemoteException();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0072  */
    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void s0(com.google.android.gms.dynamic.a r7, com.google.android.gms.internal.ads.H9 r8, java.util.ArrayList r9) throws android.os.RemoteException {
        /*
            r6 = this;
            java.lang.Object r8 = r6.a
            boolean r0 = r8 instanceof com.google.android.gms.ads.mediation.a
            if (r0 == 0) goto Lb6
            com.google.android.gms.internal.ads.L9 r0 = new com.google.android.gms.internal.ads.L9
            r1 = 10
            r0.<init>(r1)
            java.util.ArrayList r1 = new java.util.ArrayList
            r1.<init>()
            java.util.Iterator r9 = r9.iterator()
        L16:
            boolean r2 = r9.hasNext()
            if (r2 == 0) goto Laa
            java.lang.Object r2 = r9.next()
            com.google.android.gms.internal.ads.zzbme r2 = (com.google.android.gms.internal.ads.zzbme) r2
            java.lang.String r2 = r2.a
            int r3 = r2.hashCode()
            switch(r3) {
                case -1396342996: goto L68;
                case -1052618729: goto L5e;
                case -239580146: goto L54;
                case 604727084: goto L4a;
                case 1167692200: goto L40;
                case 1778294298: goto L36;
                case 1911491517: goto L2c;
                default: goto L2b;
            }
        L2b:
            goto L72
        L2c:
            java.lang.String r3 = "rewarded_interstitial"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L72
            r2 = 3
            goto L73
        L36:
            java.lang.String r3 = "app_open_ad"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L72
            r2 = 6
            goto L73
        L40:
            java.lang.String r3 = "app_open"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L72
            r2 = 5
            goto L73
        L4a:
            java.lang.String r3 = "interstitial"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L72
            r2 = 1
            goto L73
        L54:
            java.lang.String r3 = "rewarded"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L72
            r2 = 2
            goto L73
        L5e:
            java.lang.String r3 = "native"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L72
            r2 = 4
            goto L73
        L68:
            java.lang.String r3 = "banner"
            boolean r2 = r2.equals(r3)
            if (r2 == 0) goto L72
            r2 = 0
            goto L73
        L72:
            r2 = -1
        L73:
            com.google.android.gms.ads.c r3 = com.google.android.gms.ads.c.APP_OPEN_AD
            r4 = 0
            switch(r2) {
                case 0: goto L9a;
                case 1: goto L97;
                case 2: goto L94;
                case 3: goto L91;
                case 4: goto L8e;
                case 5: goto L9c;
                case 6: goto L7b;
                default: goto L79;
            }
        L79:
            r3 = r4
            goto L9c
        L7b:
            com.google.android.gms.internal.ads.s7 r2 = com.google.android.gms.internal.ads.AbstractC2773w7.Pb
            com.google.android.gms.ads.internal.client.r r5 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r5 = r5.c
            java.lang.Object r2 = r5.a(r2)
            java.lang.Boolean r2 = (java.lang.Boolean) r2
            boolean r2 = r2.booleanValue()
            if (r2 == 0) goto L79
            goto L9c
        L8e:
            com.google.android.gms.ads.c r3 = com.google.android.gms.ads.c.NATIVE
            goto L9c
        L91:
            com.google.android.gms.ads.c r3 = com.google.android.gms.ads.c.REWARDED_INTERSTITIAL
            goto L9c
        L94:
            com.google.android.gms.ads.c r3 = com.google.android.gms.ads.c.REWARDED
            goto L9c
        L97:
            com.google.android.gms.ads.c r3 = com.google.android.gms.ads.c.INTERSTITIAL
            goto L9c
        L9a:
            com.google.android.gms.ads.c r3 = com.google.android.gms.ads.c.BANNER
        L9c:
            if (r3 == 0) goto L16
            com.google.android.material.shape.e r2 = new com.google.android.material.shape.e
            r3 = 9
            r2.<init>(r3)
            r1.add(r2)
            goto L16
        Laa:
            com.google.android.gms.ads.mediation.a r8 = (com.google.android.gms.ads.mediation.a) r8
            java.lang.Object r7 = com.google.android.gms.dynamic.b.I3(r7)
            android.content.Context r7 = (android.content.Context) r7
            r8.initialize(r7, r0, r1)
            return
        Lb6:
            android.os.RemoteException r7 = new android.os.RemoteException
            r7.<init>()
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.BinderC1737Na.s0(com.google.android.gms.dynamic.a, com.google.android.gms.internal.ads.H9, java.util.ArrayList):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void v() throws RemoteException {
        Object obj = this.a;
        if (obj instanceof com.google.android.gms.ads.mediation.e) {
            try {
                ((com.google.android.gms.ads.mediation.e) obj).onDestroy();
            } catch (Throwable th) {
                com.google.android.gms.ads.internal.util.client.i.f("", th);
                throw new RemoteException();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void x0(com.google.android.gms.dynamic.a aVar, com.google.android.gms.ads.internal.client.zzr zzrVar, zzm zzmVar, String str, String str2, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        Object obj = this.a;
        if (!(obj instanceof com.google.android.gms.ads.mediation.a)) {
            com.google.android.gms.ads.internal.util.client.i.h(com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.i.d("Requesting interscroller ad from adapter.");
        try {
            com.google.android.gms.ads.mediation.a aVar2 = (com.google.android.gms.ads.mediation.a) obj;
            C1732Mb c1732Mb = new C1732Mb(10, interfaceC1671Ca, aVar2);
            g4(str, zzmVar, str2);
            f4(zzmVar);
            h4(zzmVar);
            i4(zzmVar, str);
            int i = zzrVar.e;
            int i2 = zzrVar.b;
            com.google.android.gms.ads.h hVar = new com.google.android.gms.ads.h(i, i2);
            hVar.g = true;
            hVar.h = i2;
            c1732Mb.s(new com.google.android.gms.ads.b(7, aVar2.getClass().getSimpleName().concat(" does not support interscroller ads."), "com.google.android.gms.ads", null));
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            LA.j(aVar, e, "adapter.loadInterscrollerAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2911za
    public final void z3(com.google.android.gms.dynamic.a aVar, zzm zzmVar, InterfaceC2226jc interfaceC2226jc, String str) throws RemoteException {
        Object obj = this.a;
        if ((obj instanceof com.google.android.gms.ads.mediation.a) || Objects.equals(obj.getClass().getCanonicalName(), "com.google.ads.mediation.admob.AdMobAdapter")) {
            this.d = aVar;
            this.c = interfaceC2226jc;
            interfaceC2226jc.M3(new com.google.android.gms.dynamic.b(obj));
            return;
        }
        com.google.android.gms.ads.internal.util.client.i.h(com.google.android.gms.ads.mediation.a.class.getCanonicalName() + " #009 Class mismatch: " + obj.getClass().getCanonicalName());
        throw new RemoteException();
    }

    public BinderC1737Na(com.google.android.gms.ads.mediation.a aVar) {
        this();
        this.a = aVar;
    }

    public BinderC1737Na(com.google.android.gms.ads.mediation.e eVar) {
        this();
        this.a = eVar;
    }
}
