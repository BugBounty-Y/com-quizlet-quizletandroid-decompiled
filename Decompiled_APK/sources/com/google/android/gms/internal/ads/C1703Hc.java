package com.google.android.gms.internal.ads;

import android.content.Context;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.lang.ref.WeakReference;
import java.math.BigInteger;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Hc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1703Hc implements CC {
    public final /* synthetic */ int a;
    public final HC b;
    public final HC c;
    public final HC d;

    public /* synthetic */ C1703Hc(HC hc, HC hc2, HC hc3, int i) {
        this.a = i;
        this.b = hc;
        this.c = hc2;
        this.d = hc3;
    }

    public Wn a() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new Wn(c2227jd, (Object) ((C1741Ne) this.b).a(), (Object) ((Tg) this.c).a(), ((Os) ((C1969df) this.d).b).b, 0);
    }

    public com.quizlet.data.repository.classmembership.c b() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        Gj gjA = ((Hj) this.b).zzb();
        C1691Fc c1691Fc = (C1691Fc) this.c;
        AbstractC1981ds.s(c2227jd);
        return new com.quizlet.data.repository.classmembership.c(c2227jd, gjA, new C2326lq(14, c2227jd, ((Hj) c1691Fc.b).zzb(), (Ek) ((BC) c1691Fc.c).zzb(), false), (Ek) ((BC) this.d).zzb());
    }

    public com.quizlet.data.repository.folderwithcreatorinclass.e c() {
        ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) ((BC) this.b).zzb();
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        C2227jd c2227jd2 = AbstractC2270kd.b;
        AbstractC1981ds.s(c2227jd2);
        Context contextA = ((C1735Me) this.c).b.a();
        AbstractC1981ds.s(c2227jd);
        return new com.quizlet.data.repository.folderwithcreatorinclass.e(scheduledExecutorService, c2227jd, c2227jd2, new El(contextA, c2227jd, 1), BC.a((com.google.android.gms.ads.nonagon.signalgeneration.t) this.d));
    }

    public Wn d() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new Wn(c2227jd, ((BC) this.b).zzb(), (Object) ((Tg) this.c).a(), this.d.zzb(), 3);
    }

    public Wn e() {
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        return new Wn((Object) c2227jd, ((Os) ((C1969df) this.b).b).b, ((BC) this.c).zzb(), (Object) ((IC) this.d).zzb(), 4);
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        String string;
        Set setSingleton;
        switch (this.a) {
            case 0:
                com.google.android.gms.ads.internal.util.C c = (com.google.android.gms.ads.internal.util.C) ((DC) this.c).a;
                return new C1697Gc(c);
            case 1:
                VersionInfoParcel versionInfoParcelB = ((C1741Ne) this.b).b();
                JSONObject jSONObject = (JSONObject) ((BC) this.c).zzb();
                String str = (String) ((CC) this.d).zzb();
                boolean zEquals = com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_NATIVE.equals(str);
                com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
                return new C5(UUID.randomUUID().toString(), versionInfoParcelB, str, jSONObject, zEquals);
            case 2:
                return new C1883bg((InterfaceC2529qe) ((C1802Xf) this.b).b.d, (Hk) ((BC) this.c).zzb(), ((C2702ug) this.d).a());
            case 3:
                com.google.android.gms.common.util.a aVar = (com.google.android.gms.common.util.a) ((BC) this.b).zzb();
                C2098gd c2098gdB = ((C1729Le) this.c).b();
                String str2 = ((Tg) this.d).a().f;
                C1732Mb c1732Mb = c2098gdB.c;
                synchronized (c1732Mb) {
                    string = ((BigInteger) c1732Mb.b).toString();
                    c1732Mb.b = ((BigInteger) c1732Mb.b).add(BigInteger.ONE);
                    c1732Mb.c = string;
                }
                return new C1880bd(aVar, c2098gdB, string, str2);
            case 4:
                return new Jg((Context) ((BC) this.b).zzb(), ((C1741Ne) this.c).b(), ((Tg) this.d).a(), 0);
            case 5:
                Context context = (Context) ((BC) this.b).zzb();
                VersionInfoParcel versionInfoParcelB2 = ((C1741Ne) this.c).b();
                Vp vpA = ((C2702ug) this.d).a();
                zzbxs zzbxsVar = vpA.A;
                if (zzbxsVar == null) {
                    return null;
                }
                Yp yp = vpA.s;
                return new C1673Cc(context, versionInfoParcelB2, zzbxsVar, yp != null ? yp.b : null);
            case 6:
                C2014eh c2014eh = new C2014eh(((Wg) this.b).b.zzb());
                Set setZzb = ((IC) this.c).zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new C2058fh(c2014eh, setZzb, c2227jd, (ScheduledExecutorService) ((BC) this.d).zzb());
            case 7:
                Set setZzb2 = ((IC) this.b).zzb();
                Vp vpA2 = ((C2702ug) this.c).a();
                C1849aq c1849aq = (C1849aq) ((C2702ug) this.d).b.b;
                AbstractC1981ds.s(c1849aq);
                return new Ah(setZzb2, vpA2, c1849aq);
            case 8:
                return new C2361mi((Context) ((BC) this.b).zzb(), ((IC) this.c).zzb(), ((C2702ug) this.d).a());
            case 9:
                Yi yiA = ((C1969df) this.b).a();
                Zi zi = (Zi) ((C2833xi) this.c).b.zzb();
                AbstractC1981ds.s(zi);
                Executor executor = (Executor) ((BC) this.d).zzb();
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                return new C2748vj(yiA, zi, executor, c2227jd2);
            case 10:
                return b();
            case 11:
                int i = ((Tg) this.d).a().o.b;
                if (i != 0) {
                    return i + (-1) != 0 ? ((C1760Qf) this.c).a() : ((C1760Qf) this.b).a();
                }
                throw null;
            case 12:
                String str3 = ((zzbvl) ((C2239jp) this.b).b.c).h;
                AbstractC1981ds.s(str3);
                Context contextA = ((C1741Ne) this.c).a();
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                Map mapZzb = ((EC) this.d).zzb();
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.e5)).booleanValue()) {
                    C2429o6 c2429o6 = new C2429o6(new C2472p6(contextA));
                    synchronized (c2429o6) {
                        if (c2429o6.c) {
                            try {
                                C2301l7 c2301l7 = c2429o6.b;
                                c2301l7.e();
                                C2344m7.D((C2344m7) c2301l7.b, str3);
                            } catch (NullPointerException e) {
                                com.google.android.gms.ads.internal.j.C.h.h("AdMobClearcutLogger.modify", e);
                            }
                        }
                    }
                    setSingleton = Collections.singleton(new C2318li(new C2921zk(c2429o6, mapZzb), c2227jd3));
                } else {
                    setSingleton = Collections.EMPTY_SET;
                }
                AbstractC1981ds.s(setSingleton);
                return setSingleton;
            case 13:
                return new Jk((Ek) ((BC) this.b).zzb(), ((IC) this.c).zzb(), (com.google.android.gms.common.util.a) ((BC) this.d).zzb());
            case 14:
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                com.google.android.gms.ads.internal.util.client.k kVar = (com.google.android.gms.ads.internal.util.client.k) this.b.zzb();
                com.google.android.gms.ads.nonagon.signalgeneration.w wVar = (com.google.android.gms.ads.nonagon.signalgeneration.w) this.c;
                com.quizlet.data.repository.classfolder.e eVar = new com.quizlet.data.repository.classfolder.e((Context) wVar.b.zzb(), (VersionInfoParcel) ((C1741Ne) wVar.c).zzb());
                com.google.android.gms.ads.nonagon.util.logging.csi.a aVar2 = new com.google.android.gms.ads.nonagon.util.logging.csi.a();
                aVar2.a = (String) AbstractC1795We.k.o();
                return new Kk(c2227jd4, kVar, eVar, aVar2, ((C1741Ne) this.d).a());
            case 15:
                Context contextA2 = ((C1741Ne) this.b).a();
                WeakReference weakReference = ((C1741Ne) this.c).b.d;
                AbstractC1981ds.s(weakReference);
                C2536ql c2536ql = (C2536ql) ((BC) this.d).zzb();
                C2227jd c2227jd5 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd5);
                return new BinderC2707ul(contextA2, weakReference, c2536ql, c2227jd5);
            case 16:
                return c();
            case 17:
                return a();
            case 18:
                return d();
            case 19:
                C1735Me c1735Me = (C1735Me) this.b;
                C2227jd c2227jd6 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd6);
                C2281ko c2281ko = new C2281ko(c2227jd6, c1735Me.b.a(), 2);
                com.google.android.gms.common.util.a aVar3 = (com.google.android.gms.common.util.a) ((BC) this.c).zzb();
                AbstractC1981ds.s(c2227jd6);
                return new C2796wo(c2281ko, ((Long) O7.c.o()).longValue(), aVar3, c2227jd6, (Hk) ((BC) this.d).zzb());
            case 20:
                Context contextA3 = ((C1735Me) this.b).b.a();
                C2227jd c2227jd7 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd7);
                C2281ko c2281ko2 = new C2281ko(contextA3, c2227jd7, 7);
                com.google.android.gms.common.util.a aVar4 = (com.google.android.gms.common.util.a) ((BC) this.c).zzb();
                AbstractC1981ds.s(c2227jd7);
                return new C2796wo(c2281ko2, 2147483647L, aVar4, c2227jd7, (Hk) ((BC) this.d).zzb());
            case 21:
                C1735Me c1735Me2 = (C1735Me) this.b;
                C2227jd c2227jd8 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd8);
                C2281ko c2281ko3 = new C2281ko(c2227jd8, c1735Me2.b.a(), 8);
                com.google.android.gms.common.util.a aVar5 = (com.google.android.gms.common.util.a) ((BC) this.c).zzb();
                AbstractC1981ds.s(c2227jd8);
                return new C2796wo(c2281ko3, ((Long) O7.d.o()).longValue(), aVar5, c2227jd8, (Hk) ((BC) this.d).zzb());
            case EventType.WINDOW_STATE /* 22 */:
                Yn ynA = ((Ok) this.b).a();
                com.google.android.gms.common.util.a aVar6 = (com.google.android.gms.common.util.a) ((BC) this.c).zzb();
                C2227jd c2227jd9 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd9);
                return new C2796wo(ynA, ((Long) O7.a.o()).longValue(), aVar6, c2227jd9, (Hk) ((BC) this.d).zzb());
            case EventType.AUDIO /* 23 */:
                Yn ynA2 = ((Ni) this.b).a();
                com.google.android.gms.common.util.a aVar7 = (com.google.android.gms.common.util.a) ((BC) this.c).zzb();
                C2227jd c2227jd10 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd10);
                return new C2796wo(ynA2, 2147483647L, aVar7, c2227jd10, (Hk) ((BC) this.d).zzb());
            case EventType.VIDEO /* 24 */:
                C2281ko c2281koB = ((C1735Me) this.b).b();
                com.google.android.gms.common.util.a aVar8 = (com.google.android.gms.common.util.a) ((BC) this.c).zzb();
                C2227jd c2227jd11 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd11);
                return new C2796wo(c2281koB, ((Long) O7.b.o()).longValue(), aVar8, c2227jd11, (Hk) ((BC) this.d).zzb());
            case EventType.SUBS /* 25 */:
                Yn ynA3 = ((C1747Oe) this.b).a();
                com.google.android.gms.common.util.a aVar9 = (com.google.android.gms.common.util.a) ((BC) this.c).zzb();
                C2227jd c2227jd12 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd12);
                return new C2796wo(ynA3, ((Long) O7.e.o()).longValue(), aVar9, c2227jd12, (Hk) ((BC) this.d).zzb());
            case EventType.CDN /* 26 */:
                Wn wnB = ((Lo) this.b).b();
                com.google.android.gms.common.util.a aVar10 = (com.google.android.gms.common.util.a) ((BC) this.c).zzb();
                C2227jd c2227jd13 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd13);
                return new C2796wo(wnB, ((Long) O7.g.o()).longValue(), aVar10, c2227jd13, (Hk) ((BC) this.d).zzb());
            case 27:
                C2281ko c2281koD = ((C1735Me) this.b).d();
                com.google.android.gms.common.util.a aVar11 = (com.google.android.gms.common.util.a) ((BC) this.c).zzb();
                C2227jd c2227jd14 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd14);
                return new C2796wo(c2281koD, ((Long) O7.h.o()).longValue(), aVar11, c2227jd14, (Hk) ((BC) this.d).zzb());
            case 28:
                return e();
            default:
                C2227jd c2227jd15 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd15);
                return new Wn((Object) c2227jd15, (Object) ((Tg) this.b).a(), ((BC) this.c).zzb(), (Object) ((C1729Le) this.d).a(), 5);
        }
    }
}
