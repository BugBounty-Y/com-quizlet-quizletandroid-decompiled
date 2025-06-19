package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import android.view.View;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final class Qm implements InterfaceC2751vm {
    public final /* synthetic */ int a = 1;
    public final Context b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;

    public Qm(Context context, C1789Ve c1789Ve, Lq lq, Xv xv, D7 d7) {
        this.b = context;
        this.c = c1789Ve;
        this.f = lq;
        this.e = xv;
        this.d = d7;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final boolean a(C1849aq c1849aq, Vp vp) throws JSONException {
        String string;
        Yp yp;
        switch (this.a) {
            case 0:
                Context context = this.b;
                if ((context instanceof Activity) && G7.a(context)) {
                    try {
                        string = vp.v.getString("tab_url");
                    } catch (Exception unused) {
                        string = null;
                    }
                    if (!TextUtils.isEmpty(string)) {
                    }
                }
                break;
            default:
                if (((D7) this.d) == null || (yp = vp.s) == null || yp.a == null) {
                }
                break;
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2751vm
    public final com.google.common.util.concurrent.e b(C1849aq c1849aq, Vp vp) throws JSONException {
        String string;
        switch (this.a) {
            case 0:
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Yc)).booleanValue()) {
                    Fi fiA = ((Hk) this.f).a();
                    fiA.o("action", "cstm_tbs_rndr");
                    fiA.x();
                }
                try {
                    string = vp.v.getString("tab_url");
                } catch (Exception unused) {
                    string = null;
                }
                return AbstractC2025es.N(Tv.b, new Pm(this, string != null ? Uri.parse(string) : null, c1849aq, vp, (Xp) c1849aq.b.b, 0), (Executor) this.d);
            default:
                C2838xn c2838xn = new C2838xn(new View(this.b), null, new C2147hi(20, (byte) 0), (Wp) vp.u.get(0));
                C2326lq c2326lq = new C2326lq(c1849aq, vp, (String) null);
                C1789Ve c1789Ve = (C1789Ve) this.c;
                C1783Ue c1783Ue = new C1783Ue(c1789Ve.d, c1789Ve.e, c2326lq, c2838xn);
                Vg vg = (Vg) c1783Ue.J.zzb();
                C2146hh c2146hh = (C2146hh) c1783Ue.M.zzb();
                C2490pi c2490pi = (C2490pi) c1783Ue.O.zzb();
                C2361mi c2361mi = (C2361mi) c1783Ue.X.zzb();
                C1724Kf c1724Kf = (C1724Kf) c1783Ue.E.zzb();
                C2084g6 c2084g6 = new C2084g6();
                c2084g6.f = new AtomicBoolean(false);
                c2084g6.a = vg;
                c2084g6.b = c2146hh;
                c2084g6.c = c2490pi;
                c2084g6.d = c2361mi;
                c2084g6.e = c1724Kf;
                Yp yp = vp.s;
                C7 c7 = new C7(c2084g6, yp.b, yp.a);
                Jq jq = Jq.CUSTOM_RENDER_SYN;
                CallableC2154hp callableC2154hp = new CallableC2154hp(new Fi(23, this, c7), 2);
                Tv tv = Lq.d;
                List list = Collections.EMPTY_LIST;
                com.google.common.util.concurrent.e eVarD = ((C2227jd) ((Xv) this.e)).d(callableC2154hp);
                Lq lq = (Lq) this.f;
                C2084g6 c2084g6A = lq.a(new C2084g6(lq, jq, null, tv, list, eVarD).b(), Jq.CUSTOM_RENDER_ACK);
                return new C2084g6((Lq) c2084g6A.f, c2084g6A.c, (String) c2084g6A.a, (com.google.common.util.concurrent.e) c2084g6A.b, (List) c2084g6A.d, AbstractC2025es.N((com.google.common.util.concurrent.e) c2084g6A.e, new C2525qa(1, AbstractC2025es.E(c1783Ue.O())), AbstractC2270kd.g)).b();
        }
    }

    public Qm(Context context, Executor executor, C1813Ze c1813Ze, Up up, Hk hk) {
        this.b = context;
        this.c = c1813Ze;
        this.d = executor;
        this.e = up;
        this.f = hk;
    }
}
