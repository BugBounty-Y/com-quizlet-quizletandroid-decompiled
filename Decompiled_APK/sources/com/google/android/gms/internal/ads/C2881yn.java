package com.google.android.gms.internal.ads;

import android.os.Binder;
import android.os.Bundle;
import android.os.RemoteException;
import android.os.SystemClock;
import android.text.TextUtils;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.zzt;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.yn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2881yn implements K3, InterfaceC2356md, com.google.android.gms.ads.mediation.c, InterfaceC2589rw, InterfaceC1681De, Pv, Xh, com.google.android.gms.ads.internal.g, Ol, InterfaceC2316lg, InterfaceC1687Ee, Ev, Ep, Rn {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ C2881yn(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void E(Throwable th) {
    }

    private final void v(Throwable th) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1681De
    public void A(String str, int i, String str2, boolean z) {
        ((C2257k6) this.b).e();
    }

    public com.google.common.util.concurrent.e I(Fp fp, Dp dp, Qg qg) {
        Pg pgH = dp.h((Cp) fp.c);
        pgH.b(new Gp());
        Qg qg2 = (Qg) pgH.g();
        this.b = qg2;
        C2831xg c2831xgZzb = qg2.zzb();
        C2755vq c2755vq = new C2755vq();
        Nv nvT = Nv.t(c2831xgZzb.b());
        C2439oa c2439oa = new C2439oa(12, c2755vq, c2831xgZzb);
        Kv kv = Kv.a;
        return AbstractC2025es.L(AbstractC2025es.N(nvT, c2439oa, kv), new C1804Yb(c2755vq, 7), kv);
    }

    public int K() {
        int iOptInt = ((JSONObject) this.b).optInt("media_type", -1);
        if (iOptInt != 0) {
            return iOptInt != 1 ? 3 : 1;
        }
        return 2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r12v6 */
    public List M(I3 i3) {
        String str;
        int i;
        List listSingletonList;
        Kn kn = new Kn((byte[]) i3.d);
        ArrayList arrayList = (Bu) this.b;
        while (kn.s() > 0) {
            int iZ = kn.z();
            int iZ2 = kn.b + kn.z();
            if (iZ == 134) {
                arrayList = new ArrayList();
                int iZ3 = kn.z() & 31;
                for (int i2 = 0; i2 < iZ3; i2++) {
                    String strB = kn.b(3, StandardCharsets.UTF_8);
                    int iZ4 = kn.z();
                    boolean z = (iZ4 & 128) != 0;
                    if (z) {
                        i = iZ4 & 63;
                        str = "application/cea-708";
                    } else {
                        str = "application/cea-608";
                        i = 1;
                    }
                    byte bZ = (byte) kn.z();
                    kn.k(1);
                    if (z) {
                        int i4 = bZ & 64;
                        byte[] bArr = Hi.a;
                        listSingletonList = Collections.singletonList(i4 != 0 ? new byte[]{1} : new byte[]{0});
                    } else {
                        listSingletonList = null;
                    }
                    EF ef = new EF();
                    ef.d(str);
                    ef.d = strB;
                    ef.G = i;
                    ef.o = listSingletonList;
                    arrayList.add(new C1832aG(ef));
                }
            }
            kn.j(iZ2);
            arrayList = arrayList;
        }
        return arrayList;
    }

    @Override // com.google.android.gms.ads.internal.g
    public void a() {
        ScheduledFuture scheduledFuture;
        ScheduledFuture scheduledFuture2;
        Gh gh = ((C2406nk) this.b).g;
        synchronized (gh) {
            try {
                if (gh.i) {
                    if (gh.g > 0 && (scheduledFuture2 = gh.j) != null && scheduledFuture2.isCancelled()) {
                        gh.m1(gh.g);
                    }
                    if (gh.h > 0 && (scheduledFuture = gh.k) != null && scheduledFuture.isCancelled()) {
                        gh.n1(gh.h);
                    }
                    gh.i = false;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Xh
    /* renamed from: b */
    public void mo16b(Object obj) {
        switch (this.a) {
            case 13:
                ((InterfaceC1884bh) obj).E((zzdgh) this.b);
                break;
            case 14:
                ((Bh) obj).d((zzt) this.b);
                break;
            case 15:
            default:
                Iq iq = (Iq) this.b;
                ((Mq) obj).c((Jq) iq.a, iq.b);
                break;
            case 16:
                ((InterfaceC2618si) obj).b((com.google.android.gms.ads.nonagon.signalgeneration.q) this.b);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        switch (this.a) {
            case 11:
                String str = (String) obj;
                C1682Df c1682Df = (C1682Df) this.b;
                C2155hq c2155hq = c1682Df.h;
                Vp vp = c1682Df.f;
                c2155hq.b(true == com.google.android.gms.ads.internal.j.C.h.a(c1682Df.a) ? 2 : 1, c1682Df.g.c(c1682Df.e, vp, false, "", str, vp.c));
                return;
            case 12:
                ((C2831xg) this.b).f.o(true);
                return;
            case 17:
                try {
                    InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) ((List) obj).get(0);
                    if (interfaceC2529qe != null) {
                        C2748vj c2748vj = (C2748vj) this.b;
                        c2748vj.getClass();
                        c2748vj.c.execute(new RunnableC1970dg(interfaceC2529qe, 3));
                        return;
                    }
                    return;
                } catch (ClassCastException | IndexOutOfBoundsException e) {
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.s5)).booleanValue()) {
                        com.google.android.gms.ads.internal.j.C.h.h("omid native display exp", e);
                        return;
                    }
                    return;
                }
            case 19:
                String str2 = (String) obj;
                synchronized (this) {
                    C1931cl c1931cl = (C1931cl) this.b;
                    c1931cl.c = true;
                    com.google.android.gms.ads.internal.j.C.k.getClass();
                    c1931cl.d("com.google.android.gms.ads.MobileAds", (int) (SystemClock.elapsedRealtime() - c1931cl.d), "", true);
                    c1931cl.i.execute(new Qv(28, this, str2));
                }
                return;
            default:
                ((Ll) this.b).c.J0((C1849aq) obj);
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.Ol
    public com.google.common.util.concurrent.e d(zzbvl zzbvlVar) {
        return ((Tl) ((InterfaceC2907zC) ((C2326lq) this.b).d).zzb()).e4(zzbvlVar, Binder.getCallingUid());
    }

    @Override // com.google.android.gms.internal.ads.Ep
    public /* synthetic */ Object j() {
        return (Qg) this.b;
    }

    @Override // com.google.android.gms.internal.ads.Rn
    public void o(AbstractC2359mg abstractC2359mg) {
        Sp sp = (Sp) this.b;
        C2105gk c2105gk = (C2105gk) abstractC2359mg;
        synchronized (sp) {
            try {
                sp.j = c2105gk;
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.G3)).booleanValue()) {
                    c2105gk.s.a = sp.e;
                }
                sp.j.a();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Ep
    public /* bridge */ /* synthetic */ com.google.common.util.concurrent.e q(Fp fp, Dp dp) {
        return I(fp, dp, null);
    }

    @Override // com.google.android.gms.ads.internal.g
    public void r() {
        Gh gh = ((C2406nk) this.b).g;
        synchronized (gh) {
            try {
                if (gh.i) {
                    return;
                }
                ScheduledFuture scheduledFuture = gh.j;
                if (scheduledFuture == null || scheduledFuture.isCancelled()) {
                    gh.g = -1L;
                } else {
                    gh.j.cancel(false);
                    gh.g = gh.e - gh.d.elapsedRealtime();
                }
                ScheduledFuture scheduledFuture2 = gh.k;
                if (scheduledFuture2 == null || scheduledFuture2.isCancelled()) {
                    gh.h = -1L;
                } else {
                    gh.k.cancel(false);
                    gh.h = gh.f - gh.d.elapsedRealtime();
                }
                gh.i = true;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    @Override // com.google.android.gms.ads.mediation.c
    public void s(com.google.android.gms.ads.b bVar) {
        try {
            ((InterfaceC1809Za) this.b).r(bVar.a());
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }

    @Override // com.google.android.gms.internal.ads.K3
    /* renamed from: zza */
    public File mo18zza() {
        return (File) this.b;
    }

    public C2881yn(int i) {
        this.a = i;
        switch (i) {
            case EventType.CDN /* 26 */:
                break;
            default:
                this.b = Collections.EMPTY_LIST;
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2316lg
    public com.google.android.gms.ads.internal.client.v0 zza() throws zzfcw {
        try {
            return ((C2369mq) this.b).a.g();
        } catch (Throwable th) {
            throw new zzfcw(th);
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2589rw
    /* renamed from: zza */
    public Fw mo22zza() {
        AtomicInteger atomicInteger = C2143he.u;
        return new C1898bv((byte[]) this.b);
    }

    @Override // com.google.android.gms.internal.ads.Ev
    /* renamed from: zza */
    public com.google.common.util.concurrent.e mo19zza() {
        String lowerCase;
        Bundle bundle;
        HashMap map;
        Bundle bundle2;
        Gu guA;
        Qo qo = (Qo) this.b;
        C2601s7 c2601s7 = AbstractC2773w7.Ta;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            lowerCase = qo.e.f.toLowerCase(Locale.ROOT);
        } else {
            lowerCase = qo.e.f;
        }
        if (((Boolean) rVar.c.a(AbstractC2773w7.G1)).booleanValue()) {
            C1975dl c1975dl = qo.h;
            synchronized (c1975dl) {
                bundle = new Bundle(c1975dl.a);
            }
        } else {
            bundle = new Bundle();
        }
        Bundle bundle3 = bundle;
        ArrayList arrayList = new ArrayList();
        if (!((Boolean) rVar.c.a(AbstractC2773w7.P1)).booleanValue()) {
            Cn cn = qo.c;
            Iterator it2 = ((Du) cn.a(qo.j, lowerCase).entrySet()).iterator();
            while (it2.hasNext()) {
                Map.Entry entry = (Map.Entry) it2.next();
                String str = (String) entry.getKey();
                List list = (List) entry.getValue();
                Bundle bundle4 = qo.e.d.m;
                arrayList.add(qo.a(str, list, bundle4 != null ? bundle4.getBundle(str) : null, true, true));
            }
            synchronized (cn) {
                guA = TextUtils.isEmpty(com.google.android.gms.ads.internal.j.C.h.d().n().e) ? Gu.g : Gu.a(cn.b);
            }
            qo.b(guA, arrayList);
        } else {
            Cn cn2 = qo.c;
            String str2 = qo.j;
            synchronized (cn2) {
                try {
                    Gu guA2 = cn2.a(str2, lowerCase);
                    Gu guC = cn2.c(lowerCase);
                    map = new HashMap();
                    Iterator it3 = ((Du) guA2.entrySet()).iterator();
                    while (it3.hasNext()) {
                        Map.Entry entry2 = (Map.Entry) it3.next();
                        String str3 = (String) entry2.getKey();
                        if (guC.containsKey(str3)) {
                            Fn fn = (Fn) guC.get(str3);
                            List list2 = (List) entry2.getValue();
                            boolean z = fn.b;
                            boolean z2 = fn.c;
                            boolean z3 = fn.d;
                            if (list2 != null && !list2.isEmpty()) {
                                bundle2 = (Bundle) list2.get(0);
                            } else {
                                bundle2 = new Bundle();
                            }
                            map.put(str3, new Fn(str3, z, z2, z3, bundle2));
                        }
                    }
                    Pu puG = guC.entrySet().g();
                    while (puG.hasNext()) {
                        Map.Entry entry3 = (Map.Entry) puG.next();
                        String str4 = (String) entry3.getKey();
                        if (!map.containsKey(str4) && ((Fn) entry3.getValue()).d) {
                            map.put(str4, (Fn) entry3.getValue());
                        }
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            qo.b(map, arrayList);
        }
        AbstractC2330lu abstractC2330luN = AbstractC2330lu.n(arrayList);
        A4 a4 = new A4(9, arrayList, bundle3);
        C2227jd c2227jd = qo.a;
        Jv jv = new Jv(abstractC2330luN, true, false);
        jv.p = new Iv(jv, a4, c2227jd);
        jv.z();
        return jv;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2356md, com.google.android.gms.internal.ads.Hq
    /* renamed from: zza */
    public void mo13zza() {
        switch (this.a) {
            case 7:
                ((C1920ca) this.b).e.y();
                return;
            case EventType.AUDIO /* 23 */:
                ((InterfaceC2529qe) this.b).e0();
                return;
            default:
                Sp sp = (Sp) this.b;
                synchronized (sp) {
                    sp.j = null;
                }
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        switch (this.a) {
            case 11:
                return;
            case 12:
                ((C2831xg) this.b).f.o(false);
                return;
            case 17:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.s5)).booleanValue()) {
                    com.google.android.gms.ads.internal.j.C.h.h("omid native display exp", th);
                    return;
                }
                return;
            case 19:
                synchronized (this) {
                    C1931cl c1931cl = (C1931cl) this.b;
                    c1931cl.c = true;
                    com.google.android.gms.ads.internal.j.C.k.getClass();
                    c1931cl.d("com.google.android.gms.ads.MobileAds", (int) (SystemClock.elapsedRealtime() - c1931cl.d), "Internal Error.", false);
                    c1931cl.e.d(new Exception());
                }
                return;
            default:
                return;
        }
    }
}
