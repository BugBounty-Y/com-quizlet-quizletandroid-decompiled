package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import android.util.Pair;
import com.google.android.gms.ads.internal.client.zzm;
import java.util.HashSet;
import java.util.concurrent.Executor;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final class Kp {
    public final Context a;
    public final Executor b;
    public final C1765Re c;
    public final Ln d;
    public final Np e;
    public D7 f;
    public final Uq g;
    public final C1979dq h;
    public Iq i;

    public Kp(Context context, Executor executor, C1765Re c1765Re, Ln ln, Np np, C1979dq c1979dq) {
        this.a = context;
        this.b = executor;
        this.c = c1765Re;
        this.d = ln;
        this.h = c1979dq;
        this.e = np;
        this.g = c1765Re.c();
    }

    public final boolean a() {
        Iq iq = this.i;
        return (iq == null || iq.c.isDone()) ? false : true;
    }

    public final boolean b(zzm zzmVar, String str, AbstractC2096gb abstractC2096gb, Rn rn) throws JSONException {
        C1813Ze c1813Ze;
        Tq tq;
        Executor executor = this.b;
        if (str == null) {
            com.google.android.gms.ads.internal.util.client.i.e("Ad unit ID should not be null for interstitial ad.");
            executor.execute(new RunnableC2104gj(this, 13));
            return false;
        }
        if (a()) {
            return false;
        }
        C2601s7 c2601s7 = AbstractC2773w7.U8;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
        C1765Re c1765Re = this.c;
        if (zBooleanValue && zzmVar.f) {
            ((C2493pl) c1765Re.v.zzb()).e(true);
        }
        Pair pair = new Pair("api-call", Long.valueOf(zzmVar.z));
        com.google.android.gms.ads.internal.j.C.k.getClass();
        Bundle bundleE = AbstractC2096gb.e(pair, new Pair("dynamite-enter", Long.valueOf(System.currentTimeMillis())));
        C1979dq c1979dq = this.h;
        c1979dq.c = str;
        c1979dq.b = ((Hp) abstractC2096gb).y;
        c1979dq.a = zzmVar;
        c1979dq.t = bundleE;
        C2023eq c2023eqA = c1979dq.a();
        int iG = AbstractC2096gb.G(c2023eqA);
        Context context = this.a;
        Pq pqP = LA.p(context, iG, 4, zzmVar);
        boolean zBooleanValue2 = ((Boolean) rVar.c.a(AbstractC2773w7.i8)).booleanValue();
        Ln ln = this.d;
        if (zBooleanValue2) {
            C1765Re c1765Re2 = c1765Re.b;
            Sg sg = new Sg();
            sg.a = context;
            sg.b = c2023eqA;
            Sg sg2 = new Sg(sg);
            Yh yh = new Yh(0);
            yh.n(ln, executor);
            yh.o(ln, executor);
            c1813Ze = new C1813Ze(c1765Re2, new C2147hi(13, (byte) 0), new Zh(yh), sg2, new Ts(), new C2881yn(this.f, 0), null, null);
        } else {
            Yh yh2 = new Yh(0);
            HashSet hashSet = (HashSet) yh2.i;
            HashSet hashSet2 = (HashSet) yh2.f;
            Np np = this.e;
            if (np != null) {
                hashSet2.add(new C2318li(np, executor));
                hashSet.add(new C2318li(np, executor));
                yh2.m(np, executor);
            }
            C1765Re c1765Re3 = c1765Re.b;
            Sg sg3 = new Sg();
            sg3.a = context;
            sg3.b = c2023eqA;
            Sg sg4 = new Sg(sg3);
            yh2.n(ln, executor);
            hashSet2.add(new C2318li(ln, executor));
            hashSet.add(new C2318li(ln, executor));
            yh2.m(ln, executor);
            ((HashSet) yh2.d).add(new C2318li(ln, executor));
            yh2.p(ln, executor);
            yh2.o(ln, executor);
            ((HashSet) yh2.n).add(new C2318li(ln, executor));
            ((HashSet) yh2.m).add(new C2318li(ln, executor));
            c1813Ze = new C1813Ze(c1765Re3, new C2147hi(13, (byte) 0), new Zh(yh2), sg4, new Ts(), new C2881yn(this.f, 0), null, null);
        }
        if (((Boolean) R7.c.o()).booleanValue()) {
            tq = (Tq) c1813Ze.X.zzb();
            tq.i(4);
            tq.b(zzmVar.p);
            tq.f(zzmVar.m);
        } else {
            tq = null;
        }
        C2831xg c2831xg = (C2831xg) c1813Ze.j0.zzb();
        Iq iqA = c2831xg.a(c2831xg.b());
        this.i = iqA;
        com.quizlet.data.interactor.folderwithcreator.m mVar = new com.quizlet.data.interactor.folderwithcreator.m();
        mVar.a = rn;
        mVar.b = tq;
        mVar.c = pqP;
        mVar.d = c1813Ze;
        mVar.e = this;
        iqA.a(new Qv(0, iqA, mVar), executor);
        return true;
    }
}
