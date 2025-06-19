package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Binder;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Tl extends AbstractBinderC2814x5 implements InterfaceC1774Tb {
    public final Context a;
    public final C2227jd b;
    public final Os c;
    public final C1765Re d;
    public final ArrayDeque e;
    public final Uq f;

    public Tl(Context context, C2227jd c2227jd, L9 l9, C1765Re c1765Re, Os os, ArrayDeque arrayDeque, Uq uq) {
        super("com.google.android.gms.ads.internal.request.IAdRequestService");
        AbstractC2773w7.a(context);
        this.a = context;
        this.b = c2227jd;
        this.c = os;
        this.d = c1765Re;
        this.e = arrayDeque;
        this.f = uq;
    }

    public static Iq j4(Iq iq, Lq lq, C2267ka c2267ka, Tq tq, Pq pq) {
        com.google.android.gms.ads.internal.c cVarA = c2267ka.a("AFMA_getAdDictionary", AbstractC2224ja.b, new C2147hi(17, (byte) 0));
        AbstractC2096gb.z(iq, pq);
        Iq iqB = lq.a(iq, Jq.BUILD_URL).m(cVarA).b();
        if (!((Boolean) R7.c.o()).booleanValue()) {
            return iqB;
        }
        Nv nvT = Nv.t(iqB);
        Fp fp = new Fp(tq, false, pq, 2);
        nvT.a(new Qv(0, nvT, fp), AbstractC2270kd.g);
        return iqB;
    }

    public static Iq k4(zzbvl zzbvlVar, Lq lq, androidx.work.impl.model.n nVar) {
        C2439oa c2439oa = new C2439oa(8, nVar, zzbvlVar);
        return lq.a(AbstractC2025es.E(zzbvlVar.a), Jq.GMS_SIGNALS).m(c2439oa).k(new C2147hi(16, (byte) 0)).b();
    }

    public static void l4(com.google.common.util.concurrent.e eVar, InterfaceC1792Wb interfaceC1792Wb, zzbvl zzbvlVar) {
        C2846xv c2846xvN = AbstractC2025es.N(eVar, new C2487pf(7), AbstractC2270kd.a);
        Fi fi = new Fi(21, zzbvlVar, interfaceC1792Wb);
        c2846xvN.a(new Qv(0, c2846xvN, fi), AbstractC2270kd.g);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1774Tb
    public final void E0(zzbvl zzbvlVar, InterfaceC1792Wb interfaceC1792Wb) {
        Bundle bundle;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.h2)).booleanValue() && (bundle = zzbvlVar.m) != null) {
            AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, bundle, "service-connected");
        }
        Iq iqF4 = f4(zzbvlVar, Binder.getCallingUid());
        l4(iqF4, interfaceC1792Wb, zzbvlVar);
        if (((Boolean) W7.e.o()).booleanValue()) {
            Os os = this.c;
            Objects.requireNonNull(os);
            iqF4.a(new RunnableC2104gj(os, 5), this.b);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1774Tb
    public final void M1(String str, InterfaceC1792Wb interfaceC1792Wb) {
        l4(h4(str), interfaceC1792Wb, null);
    }

    @Override // com.google.android.gms.internal.ads.AbstractBinderC2814x5
    public final boolean d4(int i, Parcel parcel, Parcel parcel2) {
        InterfaceC1792Wb c1780Ub = null;
        C1798Xb c1798Xb = null;
        InterfaceC1792Wb c1780Ub2 = null;
        InterfaceC1792Wb c1780Ub3 = null;
        InterfaceC1792Wb c1780Ub4 = null;
        switch (i) {
            case 1:
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                parcel2.writeInt(0);
                return true;
            case 2:
                IBinder strongBinder = parcel.readStrongBinder();
                if (strongBinder != null) {
                    strongBinder.queryLocalInterface("com.google.android.gms.ads.internal.request.IAdResponseListener");
                }
                AbstractC2857y5.b(parcel);
                parcel2.writeNoException();
                return true;
            case 3:
            default:
                return false;
            case 4:
                zzbvl zzbvlVar = (zzbvl) AbstractC2857y5.a(parcel, zzbvl.CREATOR);
                IBinder strongBinder2 = parcel.readStrongBinder();
                if (strongBinder2 != null) {
                    IInterface iInterfaceQueryLocalInterface = strongBinder2.queryLocalInterface("com.google.android.gms.ads.internal.request.INonagonStreamingResponseListener");
                    c1780Ub = iInterfaceQueryLocalInterface instanceof InterfaceC1792Wb ? (InterfaceC1792Wb) iInterfaceQueryLocalInterface : new C1780Ub(strongBinder2);
                }
                AbstractC2857y5.b(parcel);
                E0(zzbvlVar, c1780Ub);
                parcel2.writeNoException();
                return true;
            case 5:
                zzbvl zzbvlVar2 = (zzbvl) AbstractC2857y5.a(parcel, zzbvl.CREATOR);
                IBinder strongBinder3 = parcel.readStrongBinder();
                if (strongBinder3 != null) {
                    IInterface iInterfaceQueryLocalInterface2 = strongBinder3.queryLocalInterface("com.google.android.gms.ads.internal.request.INonagonStreamingResponseListener");
                    c1780Ub4 = iInterfaceQueryLocalInterface2 instanceof InterfaceC1792Wb ? (InterfaceC1792Wb) iInterfaceQueryLocalInterface2 : new C1780Ub(strongBinder3);
                }
                AbstractC2857y5.b(parcel);
                h1(zzbvlVar2, c1780Ub4);
                parcel2.writeNoException();
                return true;
            case 6:
                zzbvl zzbvlVar3 = (zzbvl) AbstractC2857y5.a(parcel, zzbvl.CREATOR);
                IBinder strongBinder4 = parcel.readStrongBinder();
                if (strongBinder4 != null) {
                    IInterface iInterfaceQueryLocalInterface3 = strongBinder4.queryLocalInterface("com.google.android.gms.ads.internal.request.INonagonStreamingResponseListener");
                    c1780Ub3 = iInterfaceQueryLocalInterface3 instanceof InterfaceC1792Wb ? (InterfaceC1792Wb) iInterfaceQueryLocalInterface3 : new C1780Ub(strongBinder4);
                }
                AbstractC2857y5.b(parcel);
                x3(zzbvlVar3, c1780Ub3);
                parcel2.writeNoException();
                return true;
            case 7:
                String string = parcel.readString();
                IBinder strongBinder5 = parcel.readStrongBinder();
                if (strongBinder5 != null) {
                    IInterface iInterfaceQueryLocalInterface4 = strongBinder5.queryLocalInterface("com.google.android.gms.ads.internal.request.INonagonStreamingResponseListener");
                    c1780Ub2 = iInterfaceQueryLocalInterface4 instanceof InterfaceC1792Wb ? (InterfaceC1792Wb) iInterfaceQueryLocalInterface4 : new C1780Ub(strongBinder5);
                }
                AbstractC2857y5.b(parcel);
                M1(string, c1780Ub2);
                parcel2.writeNoException();
                return true;
            case 8:
                zzbuv zzbuvVar = (zzbuv) AbstractC2857y5.a(parcel, zzbuv.CREATOR);
                IBinder strongBinder6 = parcel.readStrongBinder();
                if (strongBinder6 != null) {
                    IInterface iInterfaceQueryLocalInterface5 = strongBinder6.queryLocalInterface("com.google.android.gms.ads.internal.request.ITrustlessTokenListener");
                    c1798Xb = iInterfaceQueryLocalInterface5 instanceof C1798Xb ? (C1798Xb) iInterfaceQueryLocalInterface5 : new C1798Xb(strongBinder6, "com.google.android.gms.ads.internal.request.ITrustlessTokenListener", 0);
                }
                AbstractC2857y5.b(parcel);
                if (((Boolean) AbstractC2216j8.a.o()).booleanValue()) {
                    this.d.getClass();
                    String str = zzbuvVar.a;
                    Tv tv = Tv.b;
                    tv.a(new Qv(0, tv, new C1732Mb(c1798Xb, false, zzbuvVar, 24)), AbstractC2270kd.g);
                } else {
                    try {
                        Parcel parcelF3 = c1798Xb.f3();
                        parcelF3.writeString("");
                        AbstractC2857y5.c(parcelF3, zzbuvVar);
                        c1798Xb.d4(1, parcelF3);
                    } catch (RemoteException unused) {
                        com.google.android.gms.ads.internal.util.A.m();
                    }
                }
                parcel2.writeNoException();
                return true;
        }
    }

    public final com.google.common.util.concurrent.e e4(final zzbvl zzbvlVar, int i) {
        if (!((Boolean) AbstractC1998e8.a.o()).booleanValue()) {
            return AbstractC2025es.C(new Exception("Split request is disabled."));
        }
        zzfej zzfejVar = zzbvlVar.i;
        if (zzfejVar == null) {
            return AbstractC2025es.C(new Exception("Pool configuration missing from request."));
        }
        if (zzfejVar.d == 0 || zzfejVar.e == 0) {
            return AbstractC2025es.C(new Exception("Caching is disabled."));
        }
        com.quizlet.data.repository.studysetwithcreator.d dVar = com.google.android.gms.ads.internal.j.C.r;
        VersionInfoParcel versionInfoParcelA = VersionInfoParcel.a();
        Uq uq = this.f;
        Context context = this.a;
        C2267ka c2267kaE = dVar.e(context, versionInfoParcelA, uq);
        C1765Re c1765Re = this.d;
        c1765Re.getClass();
        androidx.work.impl.model.n nVar = new androidx.work.impl.model.n(c1765Re.b, new com.android.billingclient.api.s(zzbvlVar, i, 16));
        Lq lq = (Lq) ((BC) nVar.d).zzb();
        final Iq iqK4 = k4(zzbvlVar, lq, nVar);
        Tq tq = (Tq) ((BC) nVar.c).zzb();
        final Pq pqF = LA.f(context, 9);
        final Iq iqJ4 = j4(iqK4, lq, c2267kaE, tq, pqF);
        Jq jq = Jq.GET_URL_AND_CACHE_KEY;
        List listAsList = Arrays.asList(iqK4, iqJ4);
        Callable callable = new Callable() { // from class: com.google.android.gms.internal.ads.Pl
            @Override // java.util.concurrent.Callable
            public final Object call() {
                Tl tl = this.a;
                Iq iq = iqJ4;
                Iq iq2 = iqK4;
                zzbvl zzbvlVar2 = zzbvlVar;
                Pq pq = pqF;
                String str = ((C1810Zb) iq.c.get()).i;
                Rl rl = new Rl((C1810Zb) iq.c.get(), (JSONObject) iq2.c.get(), zzbvlVar2.h, pq);
                synchronized (tl) {
                    synchronized (tl) {
                        int iIntValue = ((Long) AbstractC1998e8.b.o()).intValue();
                        while (true) {
                            ArrayDeque arrayDeque = tl.e;
                            if (arrayDeque.size() >= iIntValue) {
                                arrayDeque.removeFirst();
                            }
                        }
                    }
                    return new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));
                }
                tl.e.addLast(rl);
                return new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));
            }
        };
        C2244ju c2244ju = AbstractC2330lu.b;
        listAsList.getClass();
        AbstractC2330lu abstractC2330luN = AbstractC2330lu.n(listAsList);
        CallableC2516q7 callableC2516q7 = new CallableC2516q7(6);
        C2227jd c2227jd = AbstractC2270kd.g;
        Jv jv = new Jv(abstractC2330luN, true, false);
        jv.p = new Iv(jv, callableC2516q7, c2227jd);
        jv.z();
        Jv jv2 = new Jv(abstractC2330luN, true, false);
        jv2.p = new Iv(jv2, callable, lq.a);
        jv2.z();
        return new C2084g6(lq, jq, null, jv, listAsList, jv2).b();
    }

    public final Iq f4(zzbvl zzbvlVar, int i) {
        Rl rlI4;
        Iq iqB;
        com.quizlet.data.repository.studysetwithcreator.d dVar = com.google.android.gms.ads.internal.j.C.r;
        VersionInfoParcel versionInfoParcelA = VersionInfoParcel.a();
        Context context = this.a;
        C2267ka c2267kaE = dVar.e(context, versionInfoParcelA, this.f);
        C1765Re c1765Re = this.d;
        c1765Re.getClass();
        androidx.work.impl.model.n nVar = new androidx.work.impl.model.n(c1765Re.b, new com.android.billingclient.api.s(zzbvlVar, i, 16));
        com.google.android.gms.ads.internal.c cVarA = c2267kaE.a("google.afma.response.normalize", Sl.d, AbstractC2224ja.c);
        if (((Boolean) AbstractC1998e8.a.o()).booleanValue()) {
            rlI4 = i4(zzbvlVar.h);
            if (rlI4 == null) {
                com.google.android.gms.ads.internal.util.A.l("Request contained a PoolKey but no matching parameters were found.");
            }
        } else {
            String str = zzbvlVar.j;
            rlI4 = null;
            if (str != null && !str.isEmpty()) {
                com.google.android.gms.ads.internal.util.A.l("Request contained a PoolKey but split request is disabled.");
            }
        }
        Pq pqF = rlI4 == null ? LA.f(context, 9) : rlI4.d;
        Tq tq = (Tq) ((BC) nVar.c).zzb();
        tq.d(zzbvlVar.a.getStringArrayList("ad_types"));
        Yl yl = new Yl(zzbvlVar.g, tq, pqF);
        C1732Mb c1732Mb = new C1732Mb(25, context, zzbvlVar.b.a);
        Lq lq = (Lq) ((BC) nVar.d).zzb();
        Pq pqF2 = LA.f(context, 11);
        Jq jq = Jq.PRE_PROCESS;
        Jq jq2 = Jq.HTTP;
        if (rlI4 == null) {
            Iq iqK4 = k4(zzbvlVar, lq, nVar);
            Iq iqJ4 = j4(iqK4, lq, c2267kaE, tq, pqF);
            Pq pqF3 = LA.f(context, 10);
            List listAsList = Arrays.asList(iqJ4, iqK4);
            Ng ng = new Ng(iqJ4, zzbvlVar, iqK4);
            C2244ju c2244ju = AbstractC2330lu.b;
            listAsList.getClass();
            AbstractC2330lu abstractC2330luN = AbstractC2330lu.n(listAsList);
            CallableC2516q7 callableC2516q7 = new CallableC2516q7(6);
            C2227jd c2227jd = AbstractC2270kd.g;
            Jv jv = new Jv(abstractC2330luN, true, false);
            jv.p = new Iv(jv, callableC2516q7, c2227jd);
            jv.z();
            Jv jv2 = new Jv(abstractC2330luN, true, false);
            C2227jd c2227jd2 = lq.a;
            jv2.p = new Iv(jv2, ng, c2227jd2);
            jv2.z();
            Iq iqB2 = new C2084g6(lq, jq2, null, jv, listAsList, jv2).k(yl).k(new Sq(pqF3)).k(c1732Mb).b();
            AbstractC2096gb.L(iqB2, tq, pqF3, false);
            AbstractC2096gb.z(iqB2, pqF2);
            List listAsList2 = Arrays.asList(iqK4, iqJ4, iqB2);
            Aj aj = new Aj(zzbvlVar, iqB2, iqK4, iqJ4, 1);
            C2244ju c2244ju2 = AbstractC2330lu.b;
            listAsList2.getClass();
            AbstractC2330lu abstractC2330luN2 = AbstractC2330lu.n(listAsList2);
            CallableC2516q7 callableC2516q72 = new CallableC2516q7(6);
            C2227jd c2227jd3 = AbstractC2270kd.g;
            Jv jv3 = new Jv(abstractC2330luN2, true, false);
            jv3.p = new Iv(jv3, callableC2516q72, c2227jd3);
            jv3.z();
            Jv jv4 = new Jv(abstractC2330luN2, true, false);
            jv4.p = new Iv(jv4, aj, c2227jd2);
            jv4.z();
            iqB = new C2084g6(lq, jq, null, jv3, listAsList2, jv4).m(cVarA).b();
        } else {
            Xl xl = new Xl(rlI4.b, rlI4.a);
            Pq pqF4 = LA.f(context, 10);
            Iq iqB3 = lq.a(AbstractC2025es.E(xl), jq2).k(yl).k(new Sq(pqF4)).k(c1732Mb).b();
            AbstractC2096gb.L(iqB3, tq, pqF4, false);
            Tv tvE = AbstractC2025es.E(rlI4);
            AbstractC2096gb.z(iqB3, pqF2);
            List listAsList3 = Arrays.asList(iqB3, tvE);
            A4 a4 = new A4(8, iqB3, tvE);
            C2244ju c2244ju3 = AbstractC2330lu.b;
            listAsList3.getClass();
            AbstractC2330lu abstractC2330luN3 = AbstractC2330lu.n(listAsList3);
            CallableC2516q7 callableC2516q73 = new CallableC2516q7(6);
            C2227jd c2227jd4 = AbstractC2270kd.g;
            Jv jv5 = new Jv(abstractC2330luN3, true, false);
            jv5.p = new Iv(jv5, callableC2516q73, c2227jd4);
            jv5.z();
            Jv jv6 = new Jv(abstractC2330luN3, true, false);
            jv6.p = new Iv(jv6, a4, lq.a);
            jv6.z();
            iqB = new C2084g6(lq, jq, null, jv5, listAsList3, jv6).m(cVarA).b();
        }
        AbstractC2096gb.L(iqB, tq, pqF2, false);
        return iqB;
    }

    public final com.google.common.util.concurrent.e g4(zzbvl zzbvlVar, int i) {
        int i2 = 27;
        int i3 = 4;
        int i4 = 2;
        int i5 = 1;
        int i6 = 7;
        com.quizlet.data.repository.studysetwithcreator.d dVar = com.google.android.gms.ads.internal.j.C.r;
        VersionInfoParcel versionInfoParcelA = VersionInfoParcel.a();
        Context context = this.a;
        C2267ka c2267kaE = dVar.e(context, versionInfoParcelA, this.f);
        if (!((Boolean) AbstractC2130h8.a.o()).booleanValue()) {
            return AbstractC2025es.C(new Exception("Signal collection disabled."));
        }
        C1765Re c1765Re = this.d;
        c1765Re.getClass();
        com.android.billingclient.api.s sVar = new com.android.billingclient.api.s(zzbvlVar, i, 16);
        C1765Re c1765Re2 = c1765Re.b;
        BC bcB = BC.b(new Ok(c1765Re2.p, 28));
        C2239jp c2239jp = new C2239jp(sVar, i5);
        C2239jp c2239jp2 = new C2239jp(sVar, i4);
        C2239jp c2239jp3 = new C2239jp(sVar, i3);
        C1741Ne c1741Ne = c1765Re2.g;
        BC bc = c1765Re2.d;
        com.google.android.gms.ads.nonagon.signalgeneration.t tVar = new com.google.android.gms.ads.nonagon.signalgeneration.t(c1741Ne, bc, c2239jp, c2239jp2, c2239jp3, 17);
        C1735Me c1735Me = new C1735Me(c1741Ne, i2);
        C2239jp c2239jp4 = new C2239jp(sVar, 0);
        C1969df c1969df = new C1969df(c2239jp4, 23);
        C1747Oe c1747Oe = new C1747Oe(bc, c1741Ne, i6);
        C2016ej c2016ej = new C2016ej(i2);
        C2239jp c2239jp5 = new C2239jp(sVar, 3);
        C2239jp c2239jp6 = new C2239jp(sVar, 6);
        C2239jp c2239jp7 = new C2239jp(sVar, 7);
        BC bc2 = c1765Re2.O;
        Ig ig = new Ig(bc2, c2239jp5, c2239jp3, c2239jp4, bc, c2239jp6, c2239jp7);
        Lo lo = new Lo(c2239jp4, bc2, bc, 2);
        C2239jp c2239jp8 = new C2239jp(sVar, 5);
        BC bcB2 = BC.b(AbstractC1972di.E);
        BC bcB3 = BC.b(AbstractC1795We.q);
        BC bcB4 = BC.b(LA.q);
        BC bcB5 = BC.b(AbstractC2096gb.q);
        int i7 = EC.b;
        LinkedHashMap linkedHashMapO = AbstractC2543qs.o(4);
        Jq jq = Jq.GMS_SIGNALS;
        AbstractC1981ds.g(bcB2, "provider");
        linkedHashMapO.put(jq, bcB2);
        Jq jq2 = Jq.BUILD_URL;
        AbstractC1981ds.g(bcB3, "provider");
        linkedHashMapO.put(jq2, bcB3);
        Jq jq3 = Jq.HTTP;
        AbstractC1981ds.g(bcB4, "provider");
        linkedHashMapO.put(jq3, bcB4);
        Jq jq4 = Jq.PRE_PROCESS;
        AbstractC1981ds.g(bcB5, "provider");
        linkedHashMapO.put(jq4, bcB5);
        BC bcB6 = BC.b(new C1703Hc(c2239jp8, c1765Re2.g, new EC(linkedHashMapO), 12));
        int i8 = IC.c;
        List list = Collections.EMPTY_LIST;
        ArrayList arrayList = new ArrayList(1);
        arrayList.add(bcB6);
        BC bcB7 = BC.b(new Do(c1765Re2.d, new Wg(new IC(list, arrayList), 25)));
        Context context2 = c1765Re2.a.b;
        AbstractC1981ds.s(context2);
        Object objZzb = c1765Re2.K0.zzb();
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        String string = ((zzbvl) sVar.c).a.getString("ms");
        if (string == null) {
            string = "";
        }
        Yn yn = new Yn(6, c2227jd, string);
        C2227jd c2227jd2 = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd2);
        ArrayList arrayList2 = zzbvlVar.e;
        AbstractC1981ds.s(arrayList2);
        Yn yn2 = new Yn(7, c2227jd2, arrayList2);
        InterfaceC2907zC interfaceC2907zCA = BC.a(tVar);
        InterfaceC2907zC interfaceC2907zCA2 = BC.a(c1735Me);
        BC.a(c1969df);
        InterfaceC2907zC interfaceC2907zCA3 = BC.a(c1747Oe);
        InterfaceC2907zC interfaceC2907zCA4 = BC.a(c2016ej);
        BC.a(ig);
        InterfaceC2907zC interfaceC2907zCA5 = BC.a(lo);
        AbstractC1981ds.s(c2227jd2);
        Tq tq = (Tq) bcB.zzb();
        Hk hk = (Hk) c1765Re2.x.zzb();
        HashSet hashSet = new HashSet();
        hashSet.add((C2110gp) objZzb);
        hashSet.add(yn);
        hashSet.add(yn2);
        C2601s7 c2601s7 = AbstractC2773w7.M5;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            hashSet.add((Vo) interfaceC2907zCA.zzb());
        }
        C2601s7 c2601s72 = AbstractC2773w7.N5;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue()) {
            hashSet.add((Vo) interfaceC2907zCA2.zzb());
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.P5)).booleanValue()) {
            hashSet.add((Vo) interfaceC2907zCA3.zzb());
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.Q5)).booleanValue()) {
            hashSet.add((Vo) interfaceC2907zCA4.zzb());
        }
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.e3)).booleanValue()) {
            hashSet.add((Vo) interfaceC2907zCA5.zzb());
        }
        Xo xo = new Xo(context2, c2227jd2, hashSet, tq, hk);
        com.google.android.gms.ads.internal.c cVarA = c2267kaE.a("google.afma.request.getSignals", AbstractC2224ja.b, AbstractC2224ja.c);
        Pq pqF = LA.f(context, 22);
        Lq lq = (Lq) bcB7.zzb();
        Jq jq5 = Jq.GET_SIGNALS;
        Bundle bundle = zzbvlVar.a;
        C2084g6 c2084g6M = lq.a(AbstractC2025es.E(bundle), jq5).k(new Sq(pqF)).m(new C2439oa(9, xo, zzbvlVar));
        Jq jq6 = Jq.JS_SIGNALS;
        Iq iqB = ((Lq) c2084g6M.f).a(c2084g6M.b(), jq6).m(cVarA).b();
        Tq tq2 = (Tq) bcB.zzb();
        tq2.d(bundle.getStringArrayList("ad_types"));
        tq2.f(bundle.getBundle("extras"));
        AbstractC2096gb.L(iqB, tq2, pqF, true);
        if (((Boolean) W7.f.o()).booleanValue()) {
            Os os = this.c;
            Objects.requireNonNull(os);
            iqB.a(new RunnableC2104gj(os, 5), this.b);
        }
        return iqB;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1774Tb
    public final void h1(zzbvl zzbvlVar, InterfaceC1792Wb interfaceC1792Wb) {
        Bundle bundle;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.h2)).booleanValue() && (bundle = zzbvlVar.m) != null) {
            AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, bundle, "service-connected");
        }
        l4(g4(zzbvlVar, Binder.getCallingUid()), interfaceC1792Wb, zzbvlVar);
    }

    public final com.google.common.util.concurrent.e h4(String str) {
        if (((Boolean) AbstractC1998e8.a.o()).booleanValue()) {
            return i4(str) == null ? AbstractC2025es.C(new Exception("URL to be removed not found for cache key: ".concat(String.valueOf(str)))) : AbstractC2025es.E(new Ql());
        }
        return AbstractC2025es.C(new Exception("Split request is disabled."));
    }

    public final synchronized Rl i4(String str) {
        Iterator it2 = this.e.iterator();
        while (it2.hasNext()) {
            Rl rl = (Rl) it2.next();
            if (rl.c.equals(str)) {
                it2.remove();
                return rl;
            }
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1774Tb
    public final void x3(zzbvl zzbvlVar, InterfaceC1792Wb interfaceC1792Wb) {
        l4(e4(zzbvlVar, Binder.getCallingUid()), interfaceC1792Wb, zzbvlVar);
    }
}
