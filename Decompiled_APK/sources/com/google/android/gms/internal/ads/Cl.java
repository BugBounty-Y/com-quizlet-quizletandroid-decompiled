package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Binder;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class Cl implements Ml {
    public static final Pattern h = Pattern.compile("Received error HTTP response code: (.*)");
    public final com.quizlet.data.repository.explanations.textbook.a a;
    public final C2227jd b;
    public final C2023eq c;
    public final ScheduledExecutorService d;
    public final C1889bm e;
    public final Tq f;
    public final Context g;

    public Cl(Context context, C2023eq c2023eq, com.quizlet.data.repository.explanations.textbook.a aVar, C2227jd c2227jd, ScheduledExecutorService scheduledExecutorService, C1889bm c1889bm, Tq tq) {
        this.g = context;
        this.c = c2023eq;
        this.a = aVar;
        this.b = c2227jd;
        this.d = scheduledExecutorService;
        this.e = c1889bm;
        this.f = tq;
    }

    @Override // com.google.android.gms.internal.ads.Ml
    public final com.google.common.util.concurrent.e a(zzbvl zzbvlVar) {
        com.google.common.util.concurrent.e eVarA;
        com.quizlet.data.repository.explanations.textbook.a aVar = this.a;
        String str = zzbvlVar.d;
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        boolean zD = com.google.android.gms.ads.internal.util.F.d(str);
        C2227jd c2227jd = (C2227jd) aVar.b;
        if (zD) {
            eVarA = AbstractC2025es.C(new zzdyq(1));
        } else {
            eVarA = AbstractC2025es.A(((C2227jd) aVar.a).d(new A4(5, aVar, zzbvlVar)), ExecutionException.class, new C2487pf(2), c2227jd);
        }
        C2028ev c2028evA = AbstractC2025es.A(eVarA, zzdyq.class, new C2922zl(aVar, zzbvlVar, Binder.getCallingUid(), 0), c2227jd);
        Pq pqF = LA.f(this.g, 11);
        AbstractC2096gb.z(c2028evA, pqF);
        AbstractC2460ov abstractC2460ovN = AbstractC2025es.N(c2028evA, new D9(this, 6), this.b);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.C5)).booleanValue()) {
            abstractC2460ovN = AbstractC2025es.A(AbstractC2025es.O(abstractC2460ovN, ((Integer) r2.c.a(AbstractC2773w7.D5)).intValue(), TimeUnit.SECONDS, this.d), TimeoutException.class, new C2487pf(3), AbstractC2270kd.g);
        }
        AbstractC2096gb.L(abstractC2460ovN, this.f, pqF, false);
        abstractC2460ovN.a(new Qv(0, abstractC2460ovN, new Os(this, 20)), AbstractC2270kd.g);
        return abstractC2460ovN;
    }
}
