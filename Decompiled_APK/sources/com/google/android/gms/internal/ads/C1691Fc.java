package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.View;
import com.comscore.streaming.EventType;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Fc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1691Fc implements CC {
    public final /* synthetic */ int a;
    public final Object b;
    public final HC c;

    public /* synthetic */ C1691Fc(Object obj, HC hc, int i) {
        this.a = i;
        this.b = obj;
        this.c = hc;
    }

    public Fi a() {
        return new Fi(22, new Zl(((C1735Me) this.b).b.a()), (Xv) ((BC) this.c).zzb());
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        View view;
        switch (this.a) {
            case 0:
                return new SharedPreferencesOnSharedPreferenceChangeListenerC1685Ec((Context) ((DC) this.b).a, (com.google.android.gms.ads.internal.util.C) ((DC) this.c).a);
            case 1:
                Context context = (Context) ((DC) this.b).a;
                C1715Jc c1715Jc = (C1715Jc) this.c;
                return new C1757Qc(context, new Fi(10, (com.google.android.gms.common.util.a) c1715Jc.c.a, (C1697Gc) c1715Jc.b.zzb()));
            case 2:
                return new C2272kf(((EC) this.b).zzb(), ((EC) this.c).zzb());
            case 3:
                return new C2916zf(((C2702ug) this.b).a(), ((C1729Le) this.c).b());
            case 4:
                return ((com.google.firebase.messaging.u) this.b).j(((IC) this.c).zzb());
            case 5:
                return new Io(((C1703Hc) this.b).a(), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.tc)).intValue(), (ScheduledExecutorService) ((BC) this.c).zzb());
            case 6:
                return new Io(new Un(((C2192ik) this.b).b.a(), 2), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.yc)).intValue(), (ScheduledExecutorService) ((BC) this.c).zzb());
            case 7:
                return new Io(((C1703Hc) this.b).e(), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.uc)).intValue(), (ScheduledExecutorService) ((BC) this.c).zzb());
            case 8:
                Boolean bool = (Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.E5);
                bool.booleanValue();
                return true == bool.booleanValue() ? ((C1784Uf) this.b).c() : ((C1760Qf) this.c).a();
            case 9:
                return new C2013eg((InterfaceC2529qe) ((C1802Xf) this.b).b.d, (Executor) ((BC) this.c).zzb());
            case 10:
                String str = (String) ((BC) this.c).zzb();
                C2923zm c2923zm = ((Sg) this.b).f;
                return c2923zm != null ? c2923zm : new C2923zm(str);
            case 11:
                ((C1741Ne) this.c).a();
                Context context2 = ((Sg) this.b).a;
                AbstractC1981ds.s(context2);
                return context2;
            case 12:
                Set setZzb = ((IC) this.c).zzb();
                Zh zh = (Zh) this.b;
                if (((Zg) zh.q) == null) {
                    zh.q = new Zg(setZzb);
                }
                Zg zg = (Zg) zh.q;
                AbstractC1981ds.s(zg);
                return zg;
            case 13:
                Vp vpA = ((C2702ug) this.b).a();
                JSONObject jSONObject = (JSONObject) ((Mi) this.c).b.a;
                AbstractC1981ds.s(jSONObject);
                return new Zi(vpA, jSONObject);
            case 14:
                return new C2318li(new C2017ek(((Pi) this.b).b.a()), (Executor) ((BC) this.c).zzb());
            case 15:
                com.google.android.gms.ads.internal.util.q qVar = (com.google.android.gms.ads.internal.util.q) ((HC) this.b).zzb();
                com.google.android.gms.common.util.a aVar = (com.google.android.gms.common.util.a) ((BC) this.c).zzb();
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                return new C2920zj(qVar, aVar, c2227jd);
            case 16:
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                return new C2326lq(14, c2227jd2, ((Hj) this.b).zzb(), (Ek) ((BC) this.c).zzb(), false);
            case 17:
                Ui ui = (Ui) ((C2153ho) this.b).zzb();
                Yi yiA = ((C1969df) this.c).a();
                Qj qj = new Qj("com.google.android.gms.ads.internal.instream.client.IInstreamAd");
                synchronized (yiA) {
                    view = yiA.o;
                }
                qj.a = view;
                qj.b = yiA.i();
                qj.c = ui;
                qj.d = false;
                qj.e = false;
                if (yiA.m() != null) {
                    yiA.m().p0(qj);
                }
                return qj;
            case 18:
                return new C2663tk(C2326lq.s(((C1735Me) this.b).b.a()), (C2620sk) ((BC) this.c).zzb());
            case 19:
                return new C2921zk((C2429o6) ((BC) this.b).zzb(), ((EC) this.c).zzb());
            case 20:
                return new Sk((C1801Xe) ((DC) this.b).a, new S4((C2904z9) ((C1753Pe) this.c).b.a, 19));
            case 21:
                return new C2536ql(((C1741Ne) this.b).a(), ((C1741Ne) this.c).b());
            case EventType.WINDOW_STATE /* 22 */:
                C2227jd c2227jd3 = AbstractC2270kd.b;
                AbstractC1981ds.s(c2227jd3);
                C2227jd c2227jd4 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd4);
                return new com.quizlet.data.repository.explanations.textbook.a(c2227jd3, c2227jd4, new El((Context) ((Ok) this.b).b.zzb(), c2227jd4, 0), BC.a((com.google.android.gms.ads.nonagon.signalgeneration.t) this.c));
            case EventType.AUDIO /* 23 */:
                Map map = ((GC) this.b).a;
                C2227jd c2227jd5 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd5);
                return new Ll(map, c2227jd5, new Ih(((Wg) this.c).b.zzb()));
            case EventType.VIDEO /* 24 */:
                C2227jd c2227jd6 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd6);
                return new C2326lq(16, c2227jd6, ((C1735Me) this.b).a(), BC.a((com.google.android.gms.ads.nonagon.signalgeneration.t) this.c), false);
            case EventType.SUBS /* 25 */:
                return a();
            case EventType.CDN /* 26 */:
                return new C1845am(((com.google.android.gms.ads.nonagon.signalgeneration.t) this.b).b(), ((C1729Le) this.c).a());
            case 27:
                return new C1932cm(((C1691Fc) this.b).a(), ((C1729Le) this.c).a());
            case 28:
                C1889bm c1889bm = (C1889bm) ((BC) this.b).zzb();
                C1691Fc c1691Fc = (C1691Fc) this.c;
                return new C2921zk(c1889bm, new C1932cm(((C1691Fc) c1691Fc.b).a(), ((C1729Le) c1691Fc.c).a()));
            default:
                C2227jd c2227jd7 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd7);
                return new C2021eo(c2227jd7, ((Tg) this.b).a(), ((C1729Le) this.c).b(), 1);
        }
    }
}
