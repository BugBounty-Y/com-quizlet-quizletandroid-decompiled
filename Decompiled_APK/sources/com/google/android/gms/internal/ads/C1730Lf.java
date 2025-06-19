package com.google.android.gms.internal.ads;

import android.content.Context;
import android.webkit.CookieManager;
import com.comscore.streaming.EventType;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Lf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1730Lf implements CC {
    public final /* synthetic */ int a;
    public final BC b;
    public final BC c;

    public /* synthetic */ C1730Lf(BC bc, BC bc2, int i) {
        this.a = i;
        this.b = bc;
        this.c = bc2;
    }

    public Gh a() {
        return new Gh((ScheduledExecutorService) this.b.zzb(), (com.google.android.gms.common.util.a) this.c.zzb());
    }

    public C2495pn b() {
        return new C2495pn((An) this.b.zzb(), (C2663tk) this.c.zzb());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        C2227jd c2227jd;
        switch (this.a) {
            case 0:
                C5 c5 = (C5) this.b.zzb();
                C2482pa c2482pa = (C2482pa) this.c.zzb();
                C2601s7 c2601s7 = AbstractC2773w7.K5;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    c2227jd = AbstractC2270kd.c;
                } else {
                    c2227jd = ((Boolean) rVar.c.a(AbstractC2773w7.J5)).booleanValue() ? AbstractC2270kd.a : AbstractC2270kd.f;
                }
                AbstractC1981ds.s(c2227jd);
                return new C1700Gf(c5.c, c2482pa, c2227jd);
            case 1:
                C1724Kf c1724Kf = (C1724Kf) this.b.zzb();
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                Set setSingleton = ((JSONObject) this.c.zzb()) == null ? Collections.EMPTY_SET : Collections.singleton(new C2318li(c1724Kf, c2227jd2));
                AbstractC1981ds.s(setSingleton);
                return setSingleton;
            case 2:
                C1724Kf c1724Kf2 = (C1724Kf) this.b.zzb();
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                Set setSingleton2 = ((JSONObject) this.c.zzb()) == null ? Collections.EMPTY_SET : Collections.singleton(new C2318li(c1724Kf2, c2227jd3));
                AbstractC1981ds.s(setSingleton2);
                return setSingleton2;
            case 3:
                C1724Kf c1724Kf3 = (C1724Kf) this.b.zzb();
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                Set setSingleton3 = ((JSONObject) this.c.zzb()) == null ? Collections.EMPTY_SET : Collections.singleton(new C2318li(c1724Kf3, c2227jd4));
                AbstractC1981ds.s(setSingleton3);
                return setSingleton3;
            case 4:
                C1724Kf c1724Kf4 = (C1724Kf) this.b.zzb();
                C2227jd c2227jd5 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd5);
                Set setSingleton4 = ((JSONObject) this.c.zzb()) == null ? Collections.EMPTY_SET : Collections.singleton(new C2318li(c1724Kf4, c2227jd5));
                AbstractC1981ds.s(setSingleton4);
                return setSingleton4;
            case 5:
                return a();
            case 6:
                return new C2917zg((com.google.android.gms.common.util.a) this.b.zzb(), (C1880bd) this.c.zzb());
            case 7:
                return new com.google.android.gms.ads.internal.a((Context) this.b.zzb(), (InterfaceC1679Dc) this.c.zzb());
            case 8:
                return new C2318li((Lh) this.b.zzb(), (Executor) this.c.zzb());
            case 9:
                return new C2318li((Lh) this.b.zzb(), (Executor) this.c.zzb());
            case 10:
                return new C2318li((Lh) this.b.zzb(), (Executor) this.c.zzb());
            case 11:
                return new C2318li((Lh) this.b.zzb(), (Executor) this.c.zzb());
            case 12:
                return new C2318li((Lh) this.b.zzb(), (Executor) this.c.zzb());
            case 13:
                return new C2318li((Lh) this.b.zzb(), (Executor) this.c.zzb());
            case 14:
                return new C2318li((Lh) this.b.zzb(), (Executor) this.c.zzb());
            case 15:
                return new C2318li((Lh) this.b.zzb(), (Executor) this.c.zzb());
            case 16:
                return new C2919zi((C2875yh) this.b.zzb(), (C2190ii) this.c.zzb());
            case 17:
                return new Mk((String) this.b.zzb(), (Kk) this.c.zzb());
            case 18:
                return new C2278kl((C1931cl) this.b.zzb(), (C2620sk) this.c.zzb());
            case 19:
                Lq lq = (Lq) this.b.zzb();
                com.google.android.gms.ads.internal.j.C.f.getClass();
                CookieManager cookieManagerB = com.google.android.gms.ads.internal.util.G.b();
                Jq jq = Jq.WEBVIEW_COOKIE;
                Q4 q4 = new Q4(cookieManagerB, 4);
                C2227jd c2227jd6 = lq.a;
                Tv tv = Lq.d;
                List list = Collections.EMPTY_LIST;
                com.google.common.util.concurrent.e eVarD = c2227jd6.d(q4);
                TimeUnit timeUnit = TimeUnit.SECONDS;
                C2084g6 c2084g6 = new C2084g6(lq, jq, null, tv, list, AbstractC2025es.O(eVarD, 1L, TimeUnit.SECONDS, lq.b));
                C2487pf c2487pf = new C2487pf(14);
                Lq lq2 = (Lq) c2084g6.f;
                return new C2084g6(lq2, c2084g6.c, (String) c2084g6.a, (com.google.common.util.concurrent.e) c2084g6.b, (List) c2084g6.d, AbstractC2025es.A((com.google.common.util.concurrent.e) c2084g6.e, Exception.class, c2487pf, lq2.a)).b();
            case 20:
                return b();
            case 21:
                com.google.common.util.concurrent.e eVar = (com.google.common.util.concurrent.e) this.b.zzb();
                C2227jd c2227jd7 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd7);
                return new C2021eo(eVar, c2227jd7, (ScheduledExecutorService) this.c.zzb(), 0);
            case EventType.WINDOW_STATE /* 22 */:
                C2227jd c2227jd8 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd8);
                C2839xo c2839xo = new C2839xo(c2227jd8, 2);
                com.google.android.gms.common.util.a aVar = (com.google.android.gms.common.util.a) this.b.zzb();
                AbstractC1981ds.s(c2227jd8);
                return new C2796wo(c2839xo, ((Long) O7.f.o()).longValue(), aVar, c2227jd8, (Hk) this.c.zzb());
            case EventType.AUDIO /* 23 */:
                return new Up((com.google.android.gms.common.util.a) this.b.zzb(), (Hk) this.c.zzb());
            case EventType.VIDEO /* 24 */:
                return new Io((C2796wo) this.b.zzb(), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.mc)).intValue(), (ScheduledExecutorService) this.c.zzb());
            case EventType.SUBS /* 25 */:
                return new Io((C2796wo) this.b.zzb(), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.ac)).intValue(), (ScheduledExecutorService) this.c.zzb());
            default:
                return new Mo((String) this.b.zzb(), ((Integer) this.c.zzb()).intValue());
        }
    }
}
