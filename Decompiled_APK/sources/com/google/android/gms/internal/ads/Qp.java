package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import android.util.Pair;
import com.google.android.gms.ads.internal.client.zzm;
import java.util.concurrent.Executor;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final class Qp {
    public final Context a;
    public final Executor b;
    public final C1765Re c;
    public final Np d;
    public final Ep e;
    public final C1893bq f;
    public final Uq g;
    public final C1979dq h;
    public com.google.common.util.concurrent.e i;

    public Qp(Context context, Executor executor, C1765Re c1765Re, Ep ep, Np np, C1979dq c1979dq, C1893bq c1893bq) {
        this.a = context;
        this.b = executor;
        this.c = c1765Re;
        this.e = ep;
        this.d = np;
        this.h = c1979dq;
        this.f = c1893bq;
        this.g = c1765Re.c();
    }

    public final boolean a(zzm zzmVar, String str, AbstractC2096gb abstractC2096gb, Rn rn) throws JSONException {
        Tq tq;
        Executor executor = this.b;
        if (str == null) {
            com.google.android.gms.ads.internal.util.client.i.e("Ad unit ID should not be null for rewarded video ad.");
            executor.execute(new RunnableC2104gj(this, 14));
            return false;
        }
        com.google.common.util.concurrent.e eVar = this.i;
        if (eVar != null && !eVar.isDone()) {
            return false;
        }
        boolean zBooleanValue = ((Boolean) R7.c.o()).booleanValue();
        Ep ep = this.e;
        if (!zBooleanValue || ep.j() == null) {
            tq = null;
        } else {
            tq = (Tq) ((C1882bf) ep.j()).g.zzb();
            tq.i(5);
            tq.b(zzmVar.p);
            tq.f(zzmVar.m);
        }
        boolean z = zzmVar.f;
        Context context = this.a;
        AbstractC1795We.g(context, z);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U8)).booleanValue() && z) {
            ((C2493pl) this.c.v.zzb()).e(true);
        }
        Pair pair = new Pair("api-call", Long.valueOf(zzmVar.z));
        com.google.android.gms.ads.internal.j.C.k.getClass();
        Bundle bundleE = AbstractC2096gb.e(pair, new Pair("dynamite-enter", Long.valueOf(System.currentTimeMillis())));
        C1979dq c1979dq = this.h;
        c1979dq.c = str;
        c1979dq.b = new com.google.android.gms.ads.internal.client.zzr("reward_mb", 0, 0, true, 0, 0, null, false, false, false, false, false, false, false, false);
        c1979dq.a = zzmVar;
        c1979dq.t = bundleE;
        C2023eq c2023eqA = c1979dq.a();
        Pq pqP = LA.p(context, AbstractC2096gb.G(c2023eqA), 5, zzmVar);
        Pp pp = new Pp();
        pp.a = c2023eqA;
        com.google.common.util.concurrent.e eVarQ = ep.q(new Fp(0, pp, null), new S4(this, 25));
        this.i = eVarQ;
        eVarQ.a(new Qv(0, eVarQ, new com.quizlet.data.repository.folderwithcreatorinclass.e(this, rn, tq, pqP, pp)), executor);
        return true;
    }

    public final com.quizlet.data.interactor.folderwithcreator.m b(Cp cp) {
        C1765Re c1765Re = this.c.b;
        com.quizlet.data.interactor.folderwithcreator.m mVar = new com.quizlet.data.interactor.folderwithcreator.m();
        mVar.a = c1765Re;
        Sg sg = new Sg();
        sg.a = this.a;
        sg.b = ((Pp) cp).a;
        sg.d = this.f;
        mVar.e = new Sg(sg);
        mVar.d = new Zh(new Yh(0));
        return mVar;
    }
}
