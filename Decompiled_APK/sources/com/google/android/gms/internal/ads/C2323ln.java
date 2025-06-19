package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.IInterface;
import com.google.android.gms.ads.internal.client.zzm;
import java.util.concurrent.Executor;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.ln, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2323ln implements Am {
    public final /* synthetic */ int a;
    public final Context b;
    public final Executor c;
    public final C1882bf d;

    public /* synthetic */ C2323ln(Context context, Executor executor, C1882bf c1882bf, int i) {
        this.a = i;
        this.b = context;
        this.c = executor;
        this.d = c1882bf;
    }

    public static final void c(C1849aq c1849aq, Vp vp, C2880ym c2880ym) {
        try {
            C2369mq c2369mq = (C2369mq) c2880ym.b;
            try {
                c2369mq.a.E2(((C2023eq) c1849aq.a.b).d, vp.v.toString());
            } catch (Throwable th) {
                throw new zzfcw(th);
            }
        } catch (Exception e) {
            com.google.android.gms.ads.internal.util.client.i.i("Fail to load ad from adapter ".concat(String.valueOf(c2880ym.a)), e);
        }
    }

    @Override // com.google.android.gms.internal.ads.Am
    public final void a(C1849aq c1849aq, Vp vp, C2880ym c2880ym) {
        zzfcw zzfcwVar;
        switch (this.a) {
            case 0:
                try {
                    C2023eq c2023eq = (C2023eq) c1849aq.a.b;
                    int i = c2023eq.o.b;
                    JSONObject jSONObject = vp.v;
                    IInterface iInterface = c2880ym.c;
                    Object obj = c2880ym.b;
                    Context context = this.b;
                    zzm zzmVar = c2023eq.d;
                    if (i == 3) {
                        C2369mq c2369mq = (C2369mq) obj;
                        try {
                            c2369mq.a.n1(new com.google.android.gms.dynamic.b(context), zzmVar, jSONObject.toString(), (InterfaceC1671Ca) iInterface);
                            return;
                        } finally {
                        }
                    }
                    C2369mq c2369mq2 = (C2369mq) obj;
                    try {
                        c2369mq2.a.d2(new com.google.android.gms.dynamic.b(context), zzmVar, jSONObject.toString(), (InterfaceC1671Ca) iInterface);
                        return;
                    } finally {
                    }
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.i("Fail to load ad from adapter ".concat(String.valueOf(c2880ym.a)), e);
                    return;
                }
                com.google.android.gms.ads.internal.util.client.i.i("Fail to load ad from adapter ".concat(String.valueOf(c2880ym.a)), e);
                return;
            default:
                C2369mq c2369mq3 = (C2369mq) c2880ym.b;
                if (c2369mq3.a()) {
                    c(c1849aq, vp, c2880ym);
                    return;
                }
                com.quizlet.data.repository.progress.b bVar = new com.quizlet.data.repository.progress.b(this, c1849aq, vp, c2880ym);
                IInterface iInterface2 = c2880ym.c;
                Sm sm = (Sm) iInterface2;
                synchronized (sm) {
                    sm.c = bVar;
                }
                Context context2 = this.b;
                C2023eq c2023eq2 = (C2023eq) c1849aq.a.b;
                InterfaceC2226jc interfaceC2226jc = (InterfaceC2226jc) iInterface2;
                String string = vp.v.toString();
                try {
                    c2369mq3.a.z3(new com.google.android.gms.dynamic.b(context2), c2023eq2.d, interfaceC2226jc, string);
                    return;
                } finally {
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.Am
    public final Object b(C1849aq c1849aq, Vp vp, C2880ym c2880ym) {
        switch (this.a) {
            case 0:
                C2326lq c2326lq = new C2326lq(c1849aq, vp, c2880ym.a);
                C2149hk c2149hk = new C2149hk(new Fm(c2880ym, vp, 1), null, 0);
                C1882bf c1882bf = this.d;
                C1838af c1838af = new C1838af(c1882bf.c, c1882bf.d, c2326lq, c2149hk);
                ((C2403nh) c1838af.E.zzb()).i1(new C2744vf((C2369mq) c2880ym.b, 0), this.c);
                ((Rm) c2880ym.c).f4((BinderC2409nn) c1838af.Y.zzb());
                return c1838af.O();
            default:
                C2326lq c2326lq2 = new C2326lq(c1849aq, vp, c2880ym.a);
                C2149hk c2149hk2 = new C2149hk(new C1732Mb(28, c2880ym, vp), null, 0);
                C1882bf c1882bf2 = this.d;
                C1838af c1838af2 = new C1838af(c1882bf2.c, c1882bf2.d, c2326lq2, c2149hk2);
                ((C2403nh) c1838af2.E.zzb()).i1(new C2744vf((C2369mq) c2880ym.b, 0), this.c);
                C2489ph c2489ph = (C2489ph) c1838af2.K.zzb();
                Vg vg = (Vg) c1838af2.L.zzb();
                C2875yh c2875yh = (C2875yh) c1838af2.Q.zzb();
                C2575ri c2575ri = (C2575ri) c1838af2.W.zzb();
                Sm sm = (Sm) c2880ym.c;
                BinderC2623sn binderC2623sn = new BinderC2623sn(c2875yh, vg, c2489ph, c2575ri);
                synchronized (sm) {
                    sm.a = binderC2623sn;
                }
                return c1838af2.O();
        }
    }
}
