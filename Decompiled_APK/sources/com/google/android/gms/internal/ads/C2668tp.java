package com.google.android.gms.internal.ads;

import android.app.KeyguardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.PowerManager;
import android.util.Pair;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.widget.FrameLayout;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.ads.internal.client.zzm;
import java.util.HashSet;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import org.json.JSONException;

/* renamed from: com.google.android.gms.internal.ads.tp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2668tp {
    public final Context a;
    public final Executor b;
    public final C1765Re c;
    public final Ln d;
    public final Nn e;
    public final FrameLayout f;
    public D7 g;
    public final Gh h;
    public final Uq i;
    public final Rh j;
    public final C1979dq k;
    public Iq l;
    public boolean m;
    public zze n;
    public Rn o;

    public C2668tp(Context context, Executor executor, com.google.android.gms.ads.internal.client.zzr zzrVar, C1765Re c1765Re, Ln ln, Nn nn, C1979dq c1979dq, Rh rh) {
        this.a = context;
        this.b = executor;
        this.c = c1765Re;
        this.d = ln;
        this.e = nn;
        this.k = c1979dq;
        this.h = new Gh((ScheduledExecutorService) c1765Re.d.zzb(), (com.google.android.gms.common.util.a) c1765Re.f.zzb());
        this.i = c1765Re.c();
        this.f = new FrameLayout(context);
        this.j = rh;
        c1979dq.b = zzrVar;
        this.m = true;
        this.n = null;
        this.o = null;
    }

    public final boolean a() {
        Iq iq = this.l;
        return (iq == null || iq.c.isDone()) ? false : true;
    }

    public final boolean b(zzm zzmVar, String str, AbstractC2096gb abstractC2096gb, Rn rn) throws JSONException {
        boolean z;
        C1789Ve c1789Ve;
        Executor executor = this.b;
        if (str == null) {
            com.google.android.gms.ads.internal.util.client.i.e("Ad unit ID should not be null for banner ad.");
            executor.execute(new RunnableC2104gj(this, 12));
            return false;
        }
        boolean zA = a();
        C1979dq c1979dq = this.k;
        if (!zA) {
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
            c1979dq.c = str;
            c1979dq.a = zzmVar;
            c1979dq.t = bundleE;
            C2023eq c2023eqA = c1979dq.a();
            int iG = AbstractC2096gb.G(c2023eqA);
            Context context = this.a;
            Pq pqP = LA.p(context, iG, 3, zzmVar);
            boolean zBooleanValue2 = ((Boolean) AbstractC1955d8.d.o()).booleanValue();
            Tq tq = null;
            Ln ln = this.d;
            if (!zBooleanValue2 || !c1979dq.b.k) {
                boolean zBooleanValue3 = ((Boolean) rVar.c.a(AbstractC2773w7.g8)).booleanValue();
                FrameLayout frameLayout = this.f;
                Rh rh = this.j;
                Gh gh = this.h;
                if (zBooleanValue3) {
                    C1765Re c1765Re2 = c1765Re.b;
                    Sg sg = new Sg();
                    sg.a = context;
                    sg.b = c2023eqA;
                    Sg sg2 = new Sg(sg);
                    Yh yh = new Yh(0);
                    yh.n(ln, executor);
                    yh.o(ln, executor);
                    Zh zh = new Zh(yh);
                    C2881yn c2881yn = new C2881yn(this.g, 0);
                    z = true;
                    c1789Ve = new C1789Ve(c1765Re2, new Os(frameLayout, 14), new Fi(0, C1929cj.h, tq), new C2147hi(13, (byte) 0), zh, sg2, new Ts(), c2881yn, new C1732Mb(16, gh, rh), null, null);
                } else {
                    z = true;
                    C1765Re c1765Re3 = c1765Re.b;
                    Sg sg3 = new Sg();
                    sg3.a = context;
                    sg3.b = c2023eqA;
                    Sg sg4 = new Sg(sg3);
                    Yh yh2 = new Yh(0);
                    yh2.n(ln, executor);
                    C2318li c2318li = new C2318li(ln, executor);
                    HashSet hashSet = (HashSet) yh2.d;
                    hashSet.add(c2318li);
                    hashSet.add(new C2318li(this.e, executor));
                    yh2.p(ln, executor);
                    ((HashSet) yh2.g).add(new C2318li(ln, executor));
                    ((HashSet) yh2.f).add(new C2318li(ln, executor));
                    ((HashSet) yh2.i).add(new C2318li(ln, executor));
                    yh2.m(ln, executor);
                    yh2.o(ln, executor);
                    ((HashSet) yh2.n).add(new C2318li(ln, executor));
                    Zh zh2 = new Zh(yh2);
                    C2881yn c2881yn2 = new C2881yn(this.g, 0);
                    c1789Ve = new C1789Ve(c1765Re3, new Os(frameLayout, 14), new Fi(0, C1929cj.h, tq), new C2147hi(13, (byte) 0), zh2, sg4, new Ts(), c2881yn2, new C1732Mb(16, gh, rh), null, null);
                }
                if (((Boolean) R7.c.o()).booleanValue()) {
                    tq = (Tq) c1789Ve.f0.zzb();
                    tq.i(3);
                    tq.b(zzmVar.p);
                    tq.f(zzmVar.m);
                }
                this.o = rn;
                C2831xg c2831xg = (C2831xg) c1789Ve.t0.zzb();
                Iq iqA = c2831xg.a(c2831xg.b());
                this.l = iqA;
                iqA.a(new Qv(0, iqA, new androidx.work.impl.model.i(this, tq, pqP, c1789Ve, 4)), executor);
                return z;
            }
            if (ln != null) {
                ln.m0(AbstractC1972di.x(7, null, null));
            }
        } else if (!c1979dq.p) {
            this.m = true;
            return false;
        }
        return false;
    }

    public final void c() {
        synchronized (this) {
            try {
                Iq iq = this.l;
                if (iq != null && iq.c.isDone()) {
                    try {
                        C1778Tf c1778Tf = (C1778Tf) this.l.c.get();
                        this.l = null;
                        FrameLayout frameLayout = this.f;
                        frameLayout.removeAllViews();
                        c1778Tf.getClass();
                        ViewParent parent = c1778Tf.k.getParent();
                        if (parent instanceof ViewGroup) {
                            com.google.android.gms.ads.internal.util.client.i.h("Banner view provided from " + c1778Tf.f.a + " already has a parent view. Removing its old parent.");
                            ((ViewGroup) parent).removeView(c1778Tf.k);
                        }
                        C2601s7 c2601s7 = AbstractC2773w7.g8;
                        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                            C2881yn c2881yn = c1778Tf.g.a;
                            Ln ln = this.d;
                            Lh lh = (Lh) c2881yn.b;
                            lh.b = ln;
                            lh.c = this.e;
                        }
                        frameLayout.addView(c1778Tf.k);
                        Rn rn = this.o;
                        if (rn != null) {
                            rn.o(c1778Tf);
                        }
                        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                            Executor executor = this.b;
                            Ln ln2 = this.d;
                            Objects.requireNonNull(ln2);
                            executor.execute(new RunnableC2104gj(ln2, 11));
                        }
                        int i = ((Xp) c1778Tf.a.b.b).d;
                        if (i >= 0) {
                            this.m = false;
                            Gh gh = this.h;
                            gh.k1(i);
                            gh.l1(c1778Tf.b());
                        } else {
                            this.m = true;
                            this.h.k1(c1778Tf.b());
                        }
                    } catch (InterruptedException | ExecutionException unused) {
                        e();
                        com.google.android.gms.ads.internal.util.A.m();
                        this.m = true;
                        this.h.a();
                    }
                } else if (this.l != null) {
                    com.google.android.gms.ads.internal.util.A.l("Show timer went off but there is an ongoing ad request.");
                    this.m = true;
                } else {
                    com.google.android.gms.ads.internal.util.A.l("No ad request was in progress or an ad was cached when show timer went off. Hence requesting a new ad.");
                    this.m = true;
                    this.h.a();
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final boolean d() {
        Object parent = this.f.getParent();
        if (!(parent instanceof View)) {
            return false;
        }
        View view = (View) parent;
        com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        Context context = view.getContext();
        Context applicationContext = context.getApplicationContext();
        KeyguardManager keyguardManager = null;
        PowerManager powerManager = applicationContext != null ? (PowerManager) applicationContext.getSystemService("power") : null;
        Object systemService = context.getSystemService("keyguard");
        if (systemService != null && (systemService instanceof KeyguardManager)) {
            keyguardManager = (KeyguardManager) systemService;
        }
        return com.google.android.gms.ads.internal.util.F.p(view, powerManager, keyguardManager);
    }

    public final void e() {
        this.l = null;
        zze zzeVar = this.n;
        this.n = null;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.g8)).booleanValue() && zzeVar != null) {
            this.b.execute(new RunnableC2793wl(8, this, zzeVar));
        }
        Rn rn = this.o;
        if (rn != null) {
            rn.zza();
        }
    }
}
