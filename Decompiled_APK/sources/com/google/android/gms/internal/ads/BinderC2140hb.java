package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.RemoteException;
import android.text.TextUtils;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.mediation.rtb.RtbAdapter;
import java.util.Iterator;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.hb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2140hb extends AbstractBinderC2814x5 implements InterfaceC1965db {
    public static final /* synthetic */ int b = 0;
    public final RtbAdapter a;

    public BinderC2140hb(RtbAdapter rtbAdapter) {
        super("com.google.android.gms.ads.internal.mediation.client.rtb.IRtbAdapter");
        this.a = rtbAdapter;
    }

    public static final void f4(String str) throws RemoteException {
        com.google.android.gms.ads.internal.util.client.i.h("Server parameters: ".concat(String.valueOf(str)));
        try {
            new Bundle();
            if (str != null) {
                JSONObject jSONObject = new JSONObject(str);
                Bundle bundle = new Bundle();
                Iterator<String> itKeys = jSONObject.keys();
                while (itKeys.hasNext()) {
                    String next = itKeys.next();
                    bundle.putString(next, jSONObject.getString(next));
                }
            }
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
            throw new RemoteException();
        }
    }

    public static final void g4(zzm zzmVar) {
        if (zzmVar.f) {
            return;
        }
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        com.google.android.gms.ads.internal.util.client.c.l();
    }

    public static final void h4(zzm zzmVar, String str) throws JSONException {
        String str2 = zzmVar.u;
        try {
            new JSONObject(str).getString("max_ad_content_rating");
        } catch (JSONException unused) {
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final boolean B3(com.google.android.gms.dynamic.b bVar) {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final void D3(String str) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final void K3(String str, String str2, zzm zzmVar, com.google.android.gms.dynamic.a aVar, InterfaceC1779Ua interfaceC1779Ua, InterfaceC1671Ca interfaceC1671Ca, com.google.android.gms.ads.internal.client.zzr zzrVar) throws RemoteException {
        try {
            RtbAdapter rtbAdapter = this.a;
            f4(str2);
            e4(zzmVar);
            g4(zzmVar);
            h4(zzmVar, str2);
            new com.google.android.gms.ads.h(zzrVar.e, zzrVar.b, zzrVar.a);
            try {
                interfaceC1779Ua.r(new zze(7, rtbAdapter.getClass().getSimpleName().concat(" does not support interscroller ads."), "com.google.android.gms.ads", null, null));
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.f("", e);
            }
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("Adapter failed to render interscroller ad.", th);
            LA.j(aVar, th, "adapter.loadRtbInterscrollerAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final void L1(String str, String str2, zzm zzmVar, com.google.android.gms.dynamic.a aVar, InterfaceC1878bb interfaceC1878bb, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        try {
            S4 s4 = new S4(interfaceC1878bb, 7);
            RtbAdapter rtbAdapter = this.a;
            f4(str2);
            e4(zzmVar);
            g4(zzmVar);
            h4(zzmVar, str2);
            rtbAdapter.loadRtbRewardedInterstitialAd(new com.google.android.gms.ads.mediation.m(), s4);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("Adapter failed to render rewarded interstitial ad.", th);
            LA.j(aVar, th, "adapter.loadRtbRewardedInterstitialAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final void L3(String str, String str2, zzm zzmVar, com.google.android.gms.dynamic.a aVar, InterfaceC1767Sa interfaceC1767Sa, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        try {
            Ts ts = new Ts(interfaceC1767Sa, 11);
            RtbAdapter rtbAdapter = this.a;
            f4(str2);
            e4(zzmVar);
            g4(zzmVar);
            h4(zzmVar, str2);
            rtbAdapter.loadRtbAppOpenAd(new com.google.android.gms.ads.mediation.f(), ts);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("Adapter failed to render app open ad.", th);
            LA.j(aVar, th, "adapter.loadRtbAppOpenAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final void O0(String str, String str2, zzm zzmVar, com.google.android.gms.dynamic.b bVar, BinderC1846an binderC1846an, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        u1(str, str2, zzmVar, bVar, binderC1846an, interfaceC1671Ca, null);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final boolean U(com.google.android.gms.dynamic.a aVar) {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final boolean W(com.google.android.gms.dynamic.a aVar) {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final void Z1(String str, String str2, zzm zzmVar, com.google.android.gms.dynamic.a aVar, InterfaceC1878bb interfaceC1878bb, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        try {
            S4 s4 = new S4(interfaceC1878bb, 7);
            RtbAdapter rtbAdapter = this.a;
            f4(str2);
            e4(zzmVar);
            g4(zzmVar);
            h4(zzmVar, str2);
            rtbAdapter.loadRtbRewardedAd(new com.google.android.gms.ads.mediation.m(), s4);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("Adapter failed to render rewarded ad.", th);
            LA.j(aVar, th, "adapter.loadRtbRewardedAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) throws RemoteException {
        InterfaceC2052fb c2008eb;
        InterfaceC1797Xa c1785Va;
        InterfaceC1767Sa c1761Ra;
        InterfaceC2052fb interfaceC2052fb = null;
        InterfaceC1767Sa interfaceC1767Sa = null;
        InterfaceC1809Za c1803Ya = null;
        InterfaceC1779Ua c1773Ta = null;
        InterfaceC1878bb c1834ab = null;
        InterfaceC1809Za c1803Ya2 = null;
        InterfaceC1878bb c1834ab2 = null;
        InterfaceC1797Xa interfaceC1797Xa = null;
        InterfaceC1779Ua c1773Ta2 = null;
        if (i == 1) {
            com.google.android.gms.dynamic.a aVarV3 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
            String string = parcel.readString();
            Parcelable.Creator creator = Bundle.CREATOR;
            Bundle bundle = (Bundle) AbstractC2857y5.a(parcel, creator);
            Bundle bundle2 = (Bundle) AbstractC2857y5.a(parcel, creator);
            com.google.android.gms.ads.internal.client.zzr zzrVar = (com.google.android.gms.ads.internal.client.zzr) AbstractC2857y5.a(parcel, com.google.android.gms.ads.internal.client.zzr.CREATOR);
            IBinder strongBinder = parcel.readStrongBinder();
            if (strongBinder == null) {
                c2008eb = interfaceC2052fb;
            } else {
                IInterface iInterfaceQueryLocalInterface = strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.rtb.ISignalsCallback");
                if (iInterfaceQueryLocalInterface instanceof InterfaceC2052fb) {
                    interfaceC2052fb = (InterfaceC2052fb) iInterfaceQueryLocalInterface;
                    c2008eb = interfaceC2052fb;
                } else {
                    c2008eb = new C2008eb(strongBinder, "com.google.android.gms.ads.internal.mediation.client.rtb.ISignalsCallback", 0);
                }
            }
            AbstractC2857y5.b(parcel);
            i1(aVarV3, string, bundle, bundle2, zzrVar, c2008eb);
            parcel2.writeNoException();
            return true;
        }
        if (i == 2) {
            f();
            throw null;
        }
        if (i == 3) {
            h();
            throw null;
        }
        if (i == 5) {
            com.google.android.gms.ads.internal.client.v0 v0VarZze = zze();
            parcel2.writeNoException();
            AbstractC2857y5.e(parcel2, v0VarZze);
            return true;
        }
        if (i == 10) {
            com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
            AbstractC2857y5.b(parcel);
            parcel2.writeNoException();
            return true;
        }
        if (i == 11) {
            parcel.createStringArray();
            AbstractC2857y5.b(parcel);
            parcel2.writeNoException();
            return true;
        }
        switch (i) {
            case 13:
                String string2 = parcel.readString();
                String string3 = parcel.readString();
                zzm zzmVar = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                com.google.android.gms.dynamic.a aVarV32 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    IInterface iInterfaceQueryLocalInterface2 = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.rtb.IBannerCallback");
                    c1773Ta2 = iInterfaceQueryLocalInterface2 instanceof InterfaceC1779Ua ? (InterfaceC1779Ua) iInterfaceQueryLocalInterface2 : new C1773Ta(strongBinder2);
                }
                InterfaceC1779Ua interfaceC1779Ua = c1773Ta2;
                InterfaceC1671Ca interfaceC1671CaE4 = AbstractBinderC1665Ba.e4(parcel.readStrongBinder());
                com.google.android.gms.ads.internal.client.zzr zzrVar2 = (com.google.android.gms.ads.internal.client.zzr) AbstractC2857y5.a(parcel, com.google.android.gms.ads.internal.client.zzr.CREATOR);
                AbstractC2857y5.b(parcel);
                l2(string2, string3, zzmVar, aVarV32, interfaceC1779Ua, interfaceC1671CaE4, zzrVar2);
                parcel2.writeNoException();
                return true;
            case 14:
                String string4 = parcel.readString();
                String string5 = parcel.readString();
                zzm zzmVar2 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                com.google.android.gms.dynamic.a aVarV33 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder3 = parcel.readStrongBinder();
                if (strongBinder3 == null) {
                    c1785Va = interfaceC1797Xa;
                } else {
                    IInterface iInterfaceQueryLocalInterface3 = strongBinder3.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.rtb.IInterstitialCallback");
                    if (iInterfaceQueryLocalInterface3 instanceof InterfaceC1797Xa) {
                        interfaceC1797Xa = (InterfaceC1797Xa) iInterfaceQueryLocalInterface3;
                        c1785Va = interfaceC1797Xa;
                    } else {
                        c1785Va = new C1785Va(strongBinder3, "com.google.android.gms.ads.internal.mediation.client.rtb.IInterstitialCallback", 0);
                    }
                }
                InterfaceC1671Ca interfaceC1671CaE42 = AbstractBinderC1665Ba.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                o1(string4, string5, zzmVar2, aVarV33, c1785Va, interfaceC1671CaE42);
                parcel2.writeNoException();
                return true;
            case 15:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                parcel2.writeInt(0);
                return true;
            case 16:
                String string6 = parcel.readString();
                String string7 = parcel.readString();
                zzm zzmVar3 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                com.google.android.gms.dynamic.a aVarV34 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder4 = parcel.readStrongBinder();
                if (strongBinder4 != null) {
                    IInterface iInterfaceQueryLocalInterface4 = strongBinder4.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.rtb.IRewardedCallback");
                    c1834ab2 = iInterfaceQueryLocalInterface4 instanceof InterfaceC1878bb ? (InterfaceC1878bb) iInterfaceQueryLocalInterface4 : new C1834ab(strongBinder4);
                }
                InterfaceC1878bb interfaceC1878bb = c1834ab2;
                InterfaceC1671Ca interfaceC1671CaE43 = AbstractBinderC1665Ba.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                Z1(string6, string7, zzmVar3, aVarV34, interfaceC1878bb, interfaceC1671CaE43);
                parcel2.writeNoException();
                return true;
            case 17:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                parcel2.writeInt(0);
                return true;
            case 18:
                String string8 = parcel.readString();
                String string9 = parcel.readString();
                zzm zzmVar4 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                com.google.android.gms.dynamic.a aVarV35 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder5 = parcel.readStrongBinder();
                if (strongBinder5 != null) {
                    IInterface iInterfaceQueryLocalInterface5 = strongBinder5.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.rtb.INativeCallback");
                    c1803Ya2 = iInterfaceQueryLocalInterface5 instanceof InterfaceC1809Za ? (InterfaceC1809Za) iInterfaceQueryLocalInterface5 : new C1803Ya(strongBinder5);
                }
                InterfaceC1809Za interfaceC1809Za = c1803Ya2;
                InterfaceC1671Ca interfaceC1671CaE44 = AbstractBinderC1665Ba.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                u1(string8, string9, zzmVar4, aVarV35, interfaceC1809Za, interfaceC1671CaE44, null);
                parcel2.writeNoException();
                return true;
            case 19:
                parcel.readString();
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                return true;
            case 20:
                String string10 = parcel.readString();
                String string11 = parcel.readString();
                zzm zzmVar5 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                com.google.android.gms.dynamic.a aVarV36 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder6 = parcel.readStrongBinder();
                if (strongBinder6 != null) {
                    IInterface iInterfaceQueryLocalInterface6 = strongBinder6.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.rtb.IRewardedCallback");
                    c1834ab = iInterfaceQueryLocalInterface6 instanceof InterfaceC1878bb ? (InterfaceC1878bb) iInterfaceQueryLocalInterface6 : new C1834ab(strongBinder6);
                }
                InterfaceC1878bb interfaceC1878bb2 = c1834ab;
                InterfaceC1671Ca interfaceC1671CaE45 = AbstractBinderC1665Ba.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                L1(string10, string11, zzmVar5, aVarV36, interfaceC1878bb2, interfaceC1671CaE45);
                parcel2.writeNoException();
                return true;
            case 21:
                String string12 = parcel.readString();
                String string13 = parcel.readString();
                zzm zzmVar6 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                com.google.android.gms.dynamic.a aVarV37 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder7 = parcel.readStrongBinder();
                if (strongBinder7 != null) {
                    IInterface iInterfaceQueryLocalInterface7 = strongBinder7.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.rtb.IBannerCallback");
                    c1773Ta = iInterfaceQueryLocalInterface7 instanceof InterfaceC1779Ua ? (InterfaceC1779Ua) iInterfaceQueryLocalInterface7 : new C1773Ta(strongBinder7);
                }
                InterfaceC1779Ua interfaceC1779Ua2 = c1773Ta;
                InterfaceC1671Ca interfaceC1671CaE46 = AbstractBinderC1665Ba.e4(parcel.readStrongBinder());
                com.google.android.gms.ads.internal.client.zzr zzrVar3 = (com.google.android.gms.ads.internal.client.zzr) AbstractC2857y5.a(parcel, com.google.android.gms.ads.internal.client.zzr.CREATOR);
                AbstractC2857y5.b(parcel);
                K3(string12, string13, zzmVar6, aVarV37, interfaceC1779Ua2, interfaceC1671CaE46, zzrVar3);
                parcel2.writeNoException();
                return true;
            case EventType.WINDOW_STATE /* 22 */:
                String string14 = parcel.readString();
                String string15 = parcel.readString();
                zzm zzmVar7 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                com.google.android.gms.dynamic.a aVarV38 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder8 = parcel.readStrongBinder();
                if (strongBinder8 != null) {
                    IInterface iInterfaceQueryLocalInterface8 = strongBinder8.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.rtb.INativeCallback");
                    c1803Ya = iInterfaceQueryLocalInterface8 instanceof InterfaceC1809Za ? (InterfaceC1809Za) iInterfaceQueryLocalInterface8 : new C1803Ya(strongBinder8);
                }
                InterfaceC1809Za interfaceC1809Za2 = c1803Ya;
                InterfaceC1671Ca interfaceC1671CaE47 = AbstractBinderC1665Ba.e4(parcel.readStrongBinder());
                zzbfv zzbfvVar = (zzbfv) AbstractC2857y5.a(parcel, zzbfv.CREATOR);
                AbstractC2857y5.b(parcel);
                u1(string14, string15, zzmVar7, aVarV38, interfaceC1809Za2, interfaceC1671CaE47, zzbfvVar);
                parcel2.writeNoException();
                return true;
            case EventType.AUDIO /* 23 */:
                String string16 = parcel.readString();
                String string17 = parcel.readString();
                zzm zzmVar8 = (zzm) AbstractC2857y5.a(parcel, zzm.CREATOR);
                com.google.android.gms.dynamic.a aVarV39 = com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                IBinder strongBinder9 = parcel.readStrongBinder();
                if (strongBinder9 == null) {
                    c1761Ra = interfaceC1767Sa;
                } else {
                    IInterface iInterfaceQueryLocalInterface9 = strongBinder9.queryLocalInterface("com.google.android.gms.ads.internal.mediation.client.rtb.IAppOpenCallback");
                    if (iInterfaceQueryLocalInterface9 instanceof InterfaceC1767Sa) {
                        interfaceC1767Sa = (InterfaceC1767Sa) iInterfaceQueryLocalInterface9;
                        c1761Ra = interfaceC1767Sa;
                    } else {
                        c1761Ra = new C1761Ra(strongBinder9, "com.google.android.gms.ads.internal.mediation.client.rtb.IAppOpenCallback", 0);
                    }
                }
                InterfaceC1671Ca interfaceC1671CaE48 = AbstractBinderC1665Ba.e4(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                L3(string16, string17, zzmVar8, aVarV39, c1761Ra, interfaceC1671CaE48);
                parcel2.writeNoException();
                return true;
            case EventType.VIDEO /* 24 */:
                com.google.android.gms.dynamic.b.v3(parcel.readStrongBinder());
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                parcel2.writeInt(0);
                return true;
            default:
                return false;
        }
    }

    public final void e4(zzm zzmVar) {
        Bundle bundle = zzmVar.m;
        if (bundle == null || bundle.getBundle(this.a.getClass().getName()) == null) {
            new Bundle();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final zzbrz f() {
        this.a.getVersionInfo();
        throw null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final zzbrz h() {
        this.a.getSDKVersionInfo();
        throw null;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0059  */
    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i1(com.google.android.gms.dynamic.a r3, java.lang.String r4, android.os.Bundle r5, android.os.Bundle r6, com.google.android.gms.ads.internal.client.zzr r7, com.google.android.gms.internal.ads.InterfaceC2052fb r8) throws android.os.RemoteException {
        /*
            r2 = this;
            com.google.android.gms.internal.ads.L9 r5 = new com.google.android.gms.internal.ads.L9     // Catch: java.lang.Throwable -> L79
            r6 = 11
            r5.<init>(r6)     // Catch: java.lang.Throwable -> L79
            com.google.android.gms.ads.mediation.rtb.RtbAdapter r6 = r2.a     // Catch: java.lang.Throwable -> L79
            com.google.android.material.shape.e r8 = new com.google.android.material.shape.e     // Catch: java.lang.Throwable -> L79
            int r0 = r4.hashCode()     // Catch: java.lang.Throwable -> L79
            switch(r0) {
                case -1396342996: goto L4f;
                case -1052618729: goto L45;
                case -239580146: goto L3b;
                case 604727084: goto L31;
                case 1167692200: goto L27;
                case 1778294298: goto L1d;
                case 1911491517: goto L13;
                default: goto L12;
            }
        L12:
            goto L59
        L13:
            java.lang.String r0 = "rewarded_interstitial"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L59
            r4 = 3
            goto L5a
        L1d:
            java.lang.String r0 = "app_open_ad"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L59
            r4 = 6
            goto L5a
        L27:
            java.lang.String r0 = "app_open"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L59
            r4 = 5
            goto L5a
        L31:
            java.lang.String r0 = "interstitial"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L59
            r4 = 1
            goto L5a
        L3b:
            java.lang.String r0 = "rewarded"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L59
            r4 = 2
            goto L5a
        L45:
            java.lang.String r0 = "native"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L59
            r4 = 4
            goto L5a
        L4f:
            java.lang.String r0 = "banner"
            boolean r4 = r4.equals(r0)
            if (r4 == 0) goto L59
            r4 = 0
            goto L5a
        L59:
            r4 = -1
        L5a:
            switch(r4) {
                case 0: goto L7b;
                case 1: goto L7b;
                case 2: goto L7b;
                case 3: goto L7b;
                case 4: goto L7b;
                case 5: goto L7b;
                case 6: goto L5e;
                default: goto L5d;
            }
        L5d:
            goto L71
        L5e:
            com.google.android.gms.internal.ads.s7 r4 = com.google.android.gms.internal.ads.AbstractC2773w7.Pb     // Catch: java.lang.Throwable -> L79
            com.google.android.gms.ads.internal.client.r r0 = com.google.android.gms.ads.internal.client.r.d     // Catch: java.lang.Throwable -> L79
            com.google.android.gms.internal.ads.u7 r0 = r0.c     // Catch: java.lang.Throwable -> L79
            java.lang.Object r4 = r0.a(r4)     // Catch: java.lang.Throwable -> L79
            java.lang.Boolean r4 = (java.lang.Boolean) r4     // Catch: java.lang.Throwable -> L79
            boolean r4 = r4.booleanValue()     // Catch: java.lang.Throwable -> L79
            if (r4 == 0) goto L71
            goto L7b
        L71:
            java.lang.IllegalArgumentException r4 = new java.lang.IllegalArgumentException     // Catch: java.lang.Throwable -> L79
            java.lang.String r5 = "Internal Error"
            r4.<init>(r5)     // Catch: java.lang.Throwable -> L79
            throw r4     // Catch: java.lang.Throwable -> L79
        L79:
            r4 = move-exception
            goto La2
        L7b:
            r4 = 9
            r8.<init>(r4)     // Catch: java.lang.Throwable -> L79
            java.util.ArrayList r4 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L79
            r4.<init>()     // Catch: java.lang.Throwable -> L79
            r4.add(r8)     // Catch: java.lang.Throwable -> L79
            com.google.android.gms.ads.mediation.rtb.a r4 = new com.google.android.gms.ads.mediation.rtb.a     // Catch: java.lang.Throwable -> L79
            java.lang.Object r8 = com.google.android.gms.dynamic.b.I3(r3)     // Catch: java.lang.Throwable -> L79
            android.content.Context r8 = (android.content.Context) r8     // Catch: java.lang.Throwable -> L79
            int r8 = r7.e     // Catch: java.lang.Throwable -> L79
            int r0 = r7.b     // Catch: java.lang.Throwable -> L79
            java.lang.String r7 = r7.a     // Catch: java.lang.Throwable -> L79
            com.google.android.gms.ads.h r1 = new com.google.android.gms.ads.h     // Catch: java.lang.Throwable -> L79
            r1.<init>(r8, r0, r7)     // Catch: java.lang.Throwable -> L79
            r4.<init>()     // Catch: java.lang.Throwable -> L79
            r6.collectSignals(r4, r5)     // Catch: java.lang.Throwable -> L79
            return
        La2:
            java.lang.String r5 = "Error generating signals for RTB"
            com.google.android.gms.ads.internal.util.client.i.f(r5, r4)
            java.lang.String r5 = "adapter.collectSignals"
            com.google.android.gms.internal.ads.LA.j(r3, r4, r5)
            android.os.RemoteException r3 = new android.os.RemoteException
            r3.<init>()
            throw r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.BinderC2140hb.i1(com.google.android.gms.dynamic.a, java.lang.String, android.os.Bundle, android.os.Bundle, com.google.android.gms.ads.internal.client.zzr, com.google.android.gms.internal.ads.fb):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final void l2(String str, String str2, zzm zzmVar, com.google.android.gms.dynamic.a aVar, InterfaceC1779Ua interfaceC1779Ua, InterfaceC1671Ca interfaceC1671Ca, com.google.android.gms.ads.internal.client.zzr zzrVar) throws RemoteException {
        try {
            Ts ts = new Ts(interfaceC1779Ua, 10);
            RtbAdapter rtbAdapter = this.a;
            f4(str2);
            e4(zzmVar);
            g4(zzmVar);
            h4(zzmVar, str2);
            new com.google.android.gms.ads.h(zzrVar.e, zzrVar.b, zzrVar.a);
            rtbAdapter.loadRtbBannerAd(new com.google.android.gms.ads.mediation.g(), ts);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("Adapter failed to render banner ad.", th);
            LA.j(aVar, th, "adapter.loadRtbBannerAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final void o1(String str, String str2, zzm zzmVar, com.google.android.gms.dynamic.a aVar, InterfaceC1797Xa interfaceC1797Xa, InterfaceC1671Ca interfaceC1671Ca) throws RemoteException {
        try {
            S4 s4 = new S4(interfaceC1797Xa, 6);
            RtbAdapter rtbAdapter = this.a;
            f4(str2);
            e4(zzmVar);
            g4(zzmVar);
            h4(zzmVar, str2);
            rtbAdapter.loadRtbInterstitialAd(new com.google.android.gms.ads.mediation.i(), s4);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("Adapter failed to render interstitial ad.", th);
            LA.j(aVar, th, "adapter.loadRtbInterstitialAd");
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final void u1(String str, String str2, zzm zzmVar, com.google.android.gms.dynamic.a aVar, InterfaceC1809Za interfaceC1809Za, InterfaceC1671Ca interfaceC1671Ca, zzbfv zzbfvVar) throws RemoteException {
        RtbAdapter rtbAdapter = this.a;
        try {
            C2881yn c2881yn = new C2881yn(interfaceC1809Za, 8);
            f4(str2);
            e4(zzmVar);
            g4(zzmVar);
            h4(zzmVar, str2);
            rtbAdapter.loadRtbNativeAdMapper(new com.google.android.gms.ads.mediation.k(), c2881yn);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.i.f("Adapter failed to render native ad.", th);
            LA.j(aVar, th, "adapter.loadRtbNativeAdMapper");
            String message = th.getMessage();
            if (TextUtils.isEmpty(message) || !message.equals("Method is not found")) {
                throw new RemoteException();
            }
            try {
                Os os = new Os(interfaceC1809Za, 10);
                f4(str2);
                e4(zzmVar);
                g4(zzmVar);
                h4(zzmVar, str2);
                rtbAdapter.loadRtbNativeAd(new com.google.android.gms.ads.mediation.k(), os);
            } catch (Throwable th2) {
                com.google.android.gms.ads.internal.util.client.i.f("Adapter failed to render native ad.", th2);
                LA.j(aVar, th2, "adapter.loadRtbNativeAd");
                throw new RemoteException();
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1965db
    public final com.google.android.gms.ads.internal.client.v0 zze() {
        return null;
    }
}
