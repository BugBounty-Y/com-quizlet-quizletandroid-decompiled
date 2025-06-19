package com.google.android.gms.internal.ads;

import android.widget.FrameLayout;
import com.comscore.streaming.EventType;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.Executor;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.df, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1969df implements CC {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ C1969df(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public static androidx.work.impl.model.c b() {
        return new androidx.work.impl.model.c(new L9(23), false, new L9(22), 9);
    }

    public Yi a() {
        Yi yi = (Yi) ((S4) this.b).b;
        AbstractC1981ds.s(yi);
        return yi;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        Object nu;
        int i = 0;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                return b();
            case 1:
                return new C2530qf(new Ts(((C1735Me) obj).b.a(), 25), i);
            case 2:
                C1721Kc c1721KcI = C1721Kc.i(((C1735Me) obj).b.a());
                return new C2572rf(new Fi(10, (com.google.android.gms.common.util.b) c1721KcI.b, (C1697Gc) ((BC) c1721KcI.d).zzb()), 1);
            case 3:
                return (FrameLayout) ((Os) obj).b;
            case 4:
                return ((C1784Uf) obj).a();
            case 5:
                C1703Hc c1703Hc = (C1703Hc) obj;
                return new C2318li(new C1883bg((InterfaceC2529qe) ((C1802Xf) c1703Hc.b).b.d, (Hk) ((BC) c1703Hc.c).zzb(), ((C2702ug) c1703Hc.d).a()), AbstractC2270kd.a);
            case 6:
                C1691Fc c1691Fc = (C1691Fc) obj;
                C2013eg c2013eg = new C2013eg((InterfaceC2529qe) ((C1802Xf) c1691Fc.b).b.d, (Executor) ((BC) c1691Fc.c).zzb());
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Bc)).booleanValue()) {
                    C2318li c2318li = new C2318li(c2013eg, AbstractC2270kd.a);
                    int i2 = AbstractC2459ou.c;
                    nu = new Nu(c2318li);
                } else {
                    int i3 = AbstractC2459ou.c;
                    nu = Hu.j;
                }
                AbstractC1981ds.s(nu);
                return nu;
            case 7:
                return new C2318li(new C1796Wf((Gh) ((C2230jg) obj).b.b, i), AbstractC2270kd.g);
            case 8:
                return ((Ig) obj).a();
            case 9:
                C1839ag c1839ag = (C1839ag) obj;
                return new C2273kg(new C1727Lc(c1839ag.b.a(), c1839ag.c.a().f));
            case 10:
                return new C2402ng(((EC) obj).zzb());
            case 11:
                return ((C1730Lf) obj).a();
            case 12:
                C1929cj c1929cj = (C1929cj) ((Gi) obj).b.b;
                AbstractC1981ds.s(c1929cj);
                Set setSingleton = c1929cj.d != null ? Collections.singleton(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_BANNER) : Collections.EMPTY_SET;
                AbstractC1981ds.s(setSingleton);
                return setSingleton;
            case 13:
                Zi zi = (Zi) ((C2833xi) obj).b.zzb();
                AbstractC1981ds.s(zi);
                JSONObject jSONObject = zi.b;
                if (jSONObject != null) {
                    return jSONObject;
                }
                try {
                    return new JSONObject(zi.a.z);
                } catch (JSONException unused) {
                    return null;
                }
            case 14:
                Oi oi = new Oi(((Pi) obj).b.a());
                Wi wi = new Wi();
                wi.a = oi;
                return wi;
            case 15:
                Yi yi = (Yi) ((S4) obj).b;
                AbstractC1981ds.s(yi);
                return yi;
            case 16:
                return new C2744vf((InterfaceC2529qe) ((CC) obj).zzb(), 1);
            case 17:
                return new C2318li(new C2744vf((InterfaceC2529qe) ((CC) ((C1969df) obj).b).zzb(), 1), AbstractC2270kd.f);
            case 18:
                C2227jd c2227jd = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd);
                C1691Fc c1691Fc2 = (C1691Fc) obj;
                Set setSingleton2 = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.e5)).booleanValue() ? Collections.singleton(new C2318li(new C2921zk((C2429o6) ((BC) c1691Fc2.b).zzb(), ((EC) c1691Fc2.c).zzb()), c2227jd)) : Collections.EMPTY_SET;
                AbstractC1981ds.s(setSingleton2);
                return setSingleton2;
            case 19:
                C1747Oe c1747Oe = (C1747Oe) obj;
                Kl kl = new Kl(c1747Oe.b.a(), (C1739Nc) c1747Oe.c.zzb());
                C2227jd c2227jd2 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd2);
                return new C2318li(kl, c2227jd2);
            case 20:
                return new Os(((C1747Oe) obj).b(), 22);
            case 21:
                C1691Fc c1691Fc3 = (C1691Fc) obj;
                C1889bm c1889bm = (C1889bm) ((BC) c1691Fc3.b).zzb();
                C1691Fc c1691Fc4 = (C1691Fc) c1691Fc3.c;
                C2921zk c2921zk = new C2921zk(c1889bm, new C1932cm(((C1691Fc) c1691Fc4.b).a(), ((C1729Le) c1691Fc4.c).a()));
                C2227jd c2227jd3 = AbstractC2270kd.a;
                AbstractC1981ds.s(c2227jd3);
                return new C2318li(c2921zk, c2227jd3);
            case EventType.WINDOW_STATE /* 22 */:
                return new Un(((Tg) obj).b.c, 5);
            default:
                AbstractC1981ds.s(AbstractC2270kd.a);
                AbstractC1981ds.s(((zzbvl) ((C2239jp) obj).b.c).d);
                return new C2197ip();
        }
    }
}
