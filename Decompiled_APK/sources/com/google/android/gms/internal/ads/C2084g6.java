package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Binder;
import android.os.Bundle;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Pair;
import android.view.View;
import com.google.android.gms.ads.internal.client.InterfaceC1622x;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.ads.internal.client.zzx;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.g6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2084g6 implements com.google.android.gms.ads.internal.d, Ep {
    public Object a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;

    public C2084g6(int i) {
        switch (i) {
            case 6:
                this.a = null;
                this.b = null;
                this.c = null;
                this.d = null;
                this.e = null;
                this.f = Gw.e;
                break;
            default:
                this.a = null;
                this.b = new RunnableC1989e(this, 8);
                this.c = new Object();
                break;
        }
    }

    public static String c(C2084g6 c2084g6) {
        String str = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.X9);
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.putOpt("objectId", (Long) c2084g6.a);
            jSONObject.put("eventCategory", (String) c2084g6.b);
            jSONObject.putOpt("event", (String) c2084g6.c);
            jSONObject.putOpt("errorCode", (Integer) c2084g6.d);
            jSONObject.putOpt("rewardType", (String) c2084g6.e);
            jSONObject.putOpt("rewardAmount", (Integer) c2084g6.f);
        } catch (JSONException unused) {
            com.google.android.gms.ads.internal.util.client.i.h("Could not convert parameters to JSON.");
        }
        return androidx.compose.ui.node.B.i(str, "(\"h5adsEvent\",", jSONObject.toString(), ");");
    }

    public static /* bridge */ /* synthetic */ void p(C2084g6 c2084g6) {
        synchronized (c2084g6.c) {
            try {
                C2172i6 c2172i6 = (C2172i6) c2084g6.d;
                if (c2172i6 == null) {
                    return;
                }
                if (c2172i6.q() || ((C2172i6) c2084g6.d).r()) {
                    ((C2172i6) c2084g6.d).e();
                }
                c2084g6.d = null;
                c2084g6.f = null;
                Binder.flushPendingCommands();
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static C2093gF t(PD pd, AbstractC2330lu abstractC2330lu, C2093gF c2093gF, C2303l9 c2303l9) {
        int iA;
        A9 a9H1 = pd.h1();
        pd.d.a();
        C2221jD c2221jD = pd.c;
        c2221jD.U();
        if (c2221jD.d1.a.o()) {
            iA = 0;
        } else {
            GD gd = c2221jD.d1;
            iA = gd.a.a(gd.b.a);
        }
        Object objF = a9H1.o() ? null : a9H1.f(iA);
        if (!pd.r1() && !a9H1.o()) {
            C2303l9 c2303l9D = a9H1.d(iA, c2303l9, false);
            pd.n1();
            String str = Yo.a;
            c2303l9D.getClass();
        }
        for (int i = 0; i < abstractC2330lu.size(); i++) {
            C2093gF c2093gF2 = (C2093gF) abstractC2330lu.get(i);
            if (x(c2093gF2, objF, pd.r1(), pd.k1(), pd.l1())) {
                return c2093gF2;
            }
        }
        if (abstractC2330lu.isEmpty() && c2093gF != null && x(c2093gF, objF, pd.r1(), pd.k1(), pd.l1())) {
            return c2093gF;
        }
        return null;
    }

    public static boolean x(C2093gF c2093gF, Object obj, boolean z, int i, int i2) {
        if (!c2093gF.a.equals(obj)) {
            return false;
        }
        int i3 = c2093gF.b;
        return z ? i3 == i && c2093gF.c == i2 : i3 == -1 && c2093gF.e == -1;
    }

    @Override // com.google.android.gms.ads.internal.d
    public void a() {
        if (((AtomicBoolean) this.f).get()) {
            ((C2146hh) this.b).a();
            ((C2490pi) this.c).a();
        }
    }

    public Iq b() {
        Lq lq = (Lq) this.f;
        Object obj = this.c;
        String str = (String) this.a;
        if (str == null) {
            lq.getClass();
            str = ((Jq) obj).a;
        }
        Iq iq = new Iq(obj, str, (com.google.common.util.concurrent.e) this.e);
        lq.c.j1(new S4(iq, 27));
        RunnableC2793wl runnableC2793wl = new RunnableC2793wl(11, this, iq);
        C2227jd c2227jd = AbstractC2270kd.g;
        ((com.google.common.util.concurrent.e) this.b).a(runnableC2793wl, c2227jd);
        iq.a(new Qv(0, iq, new Fp(1, this, iq)), c2227jd);
        return iq;
    }

    public void d(int i) throws InvalidAlgorithmParameterException {
        if (i != 16 && i != 24 && i != 32) {
            throw new InvalidAlgorithmParameterException(String.format("Invalid key size %d; only 16-byte, 24-byte and 32-byte AES keys are supported", Integer.valueOf(i)));
        }
        this.a = Integer.valueOf(i);
    }

    public zzbbc e(zzbbf zzbbfVar) {
        synchronized (this.c) {
            if (((C2214j6) this.f) == null) {
                return new zzbbc();
            }
            try {
                if (((C2172i6) this.d).x()) {
                    C2214j6 c2214j6 = (C2214j6) this.f;
                    Parcel parcelF3 = c2214j6.f3();
                    AbstractC2857y5.c(parcelF3, zzbbfVar);
                    Parcel parcelY3 = c2214j6.Y3(2, parcelF3);
                    zzbbc zzbbcVar = (zzbbc) AbstractC2857y5.a(parcelY3, zzbbc.CREATOR);
                    parcelY3.recycle();
                    return zzbbcVar;
                }
                C2214j6 c2214j62 = (C2214j6) this.f;
                Parcel parcelF32 = c2214j62.f3();
                AbstractC2857y5.c(parcelF32, zzbbfVar);
                Parcel parcelY32 = c2214j62.Y3(1, parcelF32);
                zzbbc zzbbcVar2 = (zzbbc) AbstractC2857y5.a(parcelY32, zzbbc.CREATOR);
                parcelY32.recycle();
                return zzbbcVar2;
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.f("Unable to call into cache service.", e);
                return new zzbbc();
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.d
    public synchronized void f(View view) {
        if (((AtomicBoolean) this.f).compareAndSet(false, true)) {
            ((C1724Kf) this.e).K();
            ((C2361mi) this.d).k1(view);
        }
    }

    public boolean g(zzm zzmVar, String str, AbstractC2096gb abstractC2096gb, Rn rn) throws JSONException {
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        com.google.android.gms.ads.internal.util.F f = jVar.c;
        Context context = (Context) this.e;
        boolean zG = com.google.android.gms.ads.internal.util.F.g(context);
        C1765Re c1765Re = (C1765Re) this.b;
        if (zG && zzmVar.s == null) {
            com.google.android.gms.ads.internal.util.client.i.e("Failed to load the ad because app ID is missing.");
            final int i = 0;
            c1765Re.a().execute(new Runnable(this) { // from class: com.google.android.gms.internal.ads.Tn
                public final /* synthetic */ C2084g6 b;

                {
                    this.b = this;
                }

                @Override // java.lang.Runnable
                public final void run() {
                    switch (i) {
                        case 0:
                            C2326lq c2326lq = (C2326lq) this.b.c;
                            ((Qn) c2326lq.d).m0(AbstractC1972di.x(4, null, null));
                            break;
                        default:
                            C2326lq c2326lq2 = (C2326lq) this.b.c;
                            ((Qn) c2326lq2.d).m0(AbstractC1972di.x(6, null, null));
                            break;
                    }
                }
            });
            return false;
        }
        if (str == null) {
            com.google.android.gms.ads.internal.util.client.i.e("Ad unit ID should not be null for NativeAdLoader.");
            final int i2 = 1;
            c1765Re.a().execute(new Runnable(this) { // from class: com.google.android.gms.internal.ads.Tn
                public final /* synthetic */ C2084g6 b;

                {
                    this.b = this;
                }

                @Override // java.lang.Runnable
                public final void run() {
                    switch (i2) {
                        case 0:
                            C2326lq c2326lq = (C2326lq) this.b.c;
                            ((Qn) c2326lq.d).m0(AbstractC1972di.x(4, null, null));
                            break;
                        default:
                            C2326lq c2326lq2 = (C2326lq) this.b.c;
                            ((Qn) c2326lq2.d).m0(AbstractC1972di.x(6, null, null));
                            break;
                    }
                }
            });
            return false;
        }
        boolean z = zzmVar.f;
        AbstractC1795We.g(context, z);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U8)).booleanValue() && z) {
            ((C2493pl) c1765Re.v.zzb()).e(true);
        }
        jVar.k.getClass();
        Long lValueOf = Long.valueOf(System.currentTimeMillis());
        Bundle bundleE = AbstractC2096gb.e(new Pair("api-call", lValueOf), new Pair("dynamite-enter", lValueOf));
        C1979dq c1979dq = (C1979dq) this.a;
        c1979dq.a = zzmVar;
        c1979dq.t = bundleE;
        c1979dq.m = ((Sn) abstractC2096gb).y;
        C2023eq c2023eqA = c1979dq.a();
        Pq pqP = LA.p(context, AbstractC2096gb.G(c2023eqA), 8, zzmVar);
        C2326lq c2326lq = (C2326lq) this.c;
        Ln ln = (Ln) c2326lq.c;
        com.google.android.gms.ads.internal.client.P p = c2023eqA.n;
        if (p != null) {
            ln.o(p);
        }
        C1765Re c1765Re2 = c1765Re.b;
        Sg sg = new Sg();
        sg.a = context;
        sg.b = c2023eqA;
        Sg sg2 = new Sg(sg);
        Yh yh = new Yh(0);
        yh.o(ln, c1765Re.a());
        Zh zh = new Zh(yh);
        InterfaceC1622x interfaceC1622xJ = ln.j();
        Fi fi = new Fi(0, (C1929cj) c2326lq.b, interfaceC1622xJ);
        Tq tq = null;
        C1759Qe c1759Qe = new C1759Qe(c1765Re2, new Os(tq, 14), fi, new C2147hi(13, (byte) 0), zh, sg2, new Ts(), null, null);
        if (((Boolean) R7.c.o()).booleanValue()) {
            tq = (Tq) c1759Qe.e.zzb();
            tq.i(8);
            tq.b(zzmVar.p);
            tq.f(zzmVar.m);
        }
        ((C2412nq) c1765Re.J.zzb()).b(1);
        C2227jd c2227jd = AbstractC2270kd.a;
        AbstractC1981ds.s(c2227jd);
        ScheduledExecutorService scheduledExecutorService = (ScheduledExecutorService) c1765Re.d.zzb();
        C2831xg c2831xg = (C2831xg) c1759Qe.t0.zzb();
        Iq iqA = c2831xg.a(c2831xg.b());
        C2659tg c2659tg = new C2659tg(c2227jd, scheduledExecutorService, iqA);
        this.f = c2659tg;
        iqA.a(new Qv(0, iqA, new Fi(c2659tg, false, new com.quizlet.remote.model.notes.e(this, (S4) rn, tq, pqP, c1759Qe, 5), 14)), c2227jd);
        return true;
    }

    public void h(int i) throws InvalidAlgorithmParameterException {
        if (i < 16) {
            throw new InvalidAlgorithmParameterException(String.format("Invalid key size in bytes %d; HMAC key must be at least 16 bytes", Integer.valueOf(i)));
        }
        this.b = Integer.valueOf(i);
    }

    public void i(int i) throws GeneralSecurityException {
        if (i < 12 || i > 16) {
            throw new GeneralSecurityException(String.format("Invalid IV size in bytes %d; IV size must be between 12 and 16 bytes", Integer.valueOf(i)));
        }
        this.c = Integer.valueOf(i);
    }

    @Override // com.google.android.gms.internal.ads.Ep
    public Object j() {
        Qg qg;
        synchronized (this) {
            qg = (Qg) this.e;
        }
        return qg;
    }

    public C2084g6 k(Gq gq) {
        return m(new D9(gq, 14));
    }

    public void l(int i) throws GeneralSecurityException {
        if (i < 10) {
            throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; must be at least 10 bytes", Integer.valueOf(i)));
        }
        this.d = Integer.valueOf(i);
    }

    public C2084g6 m(Fv fv) {
        C2846xv c2846xvN = AbstractC2025es.N((com.google.common.util.concurrent.e) this.e, fv, ((Lq) this.f).a);
        return new C2084g6((Lq) this.f, this.c, (String) this.a, (com.google.common.util.concurrent.e) this.b, (List) this.d, c2846xvN);
    }

    public Hw n() throws GeneralSecurityException {
        if (((Integer) this.a) == null) {
            throw new GeneralSecurityException("AES key size is not set");
        }
        if (((Integer) this.b) == null) {
            throw new GeneralSecurityException("HMAC key size is not set");
        }
        if (((Integer) this.c) == null) {
            throw new GeneralSecurityException("iv size is not set");
        }
        Integer num = (Integer) this.d;
        if (num == null) {
            throw new GeneralSecurityException("tag size is not set");
        }
        if (((Ew) this.e) == null) {
            throw new GeneralSecurityException("hash type is not set");
        }
        int iIntValue = num.intValue();
        Ew ew = (Ew) this.e;
        if (ew == Ew.c) {
            if (iIntValue > 20) {
                throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; can be at most 20 bytes for SHA1", num));
            }
        } else if (ew == Ew.d) {
            if (iIntValue > 28) {
                throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; can be at most 28 bytes for SHA224", num));
            }
        } else if (ew == Ew.e) {
            if (iIntValue > 32) {
                throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; can be at most 32 bytes for SHA256", num));
            }
        } else if (ew == Ew.f) {
            if (iIntValue > 48) {
                throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; can be at most 48 bytes for SHA384", num));
            }
        } else {
            if (ew != Ew.g) {
                throw new GeneralSecurityException("unknown hash type; must be SHA1, SHA224, SHA256, SHA384 or SHA512");
            }
            if (iIntValue > 64) {
                throw new GeneralSecurityException(String.format("Invalid tag size in bytes %d; can be at most 64 bytes for SHA512", num));
            }
        }
        return new Hw(((Integer) this.a).intValue(), ((Integer) this.b).intValue(), ((Integer) this.c).intValue(), ((Integer) this.d).intValue(), (Gw) this.f, (Ew) this.e);
    }

    public com.google.common.util.concurrent.e o(C2755vq c2755vq, Fp fp) {
        Qg qg = c2755vq.a;
        this.e = qg;
        if (c2755vq.c == null) {
            qg.zzb().g = c2755vq.b;
            return ((Fi) this.a).l(fp, null, c2755vq.a);
        }
        if (qg.zze() != null) {
            C2411np c2411np = c2755vq.c.e;
            Bp bpZze = c2755vq.a.zze();
            c2411np.getClass();
            c2411np.h = (C2411np) bpZze;
        }
        return AbstractC2025es.E(c2755vq.c);
    }

    @Override // com.google.android.gms.internal.ads.Ep
    public com.google.common.util.concurrent.e q(Fp fp, Dp dp) {
        synchronized (this) {
            Pg pgH = dp.h((Cp) fp.c);
            pgH.a(new C2754vp((String) this.d));
            Qg qg = (Qg) pgH.g();
            qg.f();
            qg.f();
            zzm zzmVar = qg.f().d;
            if (zzmVar.s != null || zzmVar.x != null) {
                this.e = qg;
                return ((Fi) this.a).l(fp, dp, qg);
            }
            C2023eq c2023eqF = qg.f();
            zzm zzmVar2 = c2023eqF.d;
            String str = c2023eqF.f;
            zzx zzxVar = c2023eqF.j;
            Xv xv = (Xv) this.f;
            return AbstractC2025es.N(Nv.t(((C2326lq) this.b).n(fp, dp, qg)), new Pm(this, fp, new C2711up(dp, fp, zzmVar2, str, xv, zzxVar, null), dp, qg, 1), xv);
        }
    }

    public C2084g6 r(long j) {
        TimeUnit timeUnit = TimeUnit.SECONDS;
        Lq lq = (Lq) this.f;
        return new C2084g6(lq, this.c, (String) this.a, (com.google.common.util.concurrent.e) this.b, (List) this.d, AbstractC2025es.O((com.google.common.util.concurrent.e) this.e, j, timeUnit, lq.b));
    }

    public void s(Context context) {
        if (context == null) {
            return;
        }
        synchronized (this.c) {
            try {
                if (((Context) this.e) != null) {
                    return;
                }
                this.e = context.getApplicationContext();
                C2601s7 c2601s7 = AbstractC2773w7.n4;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                    v();
                } else {
                    if (((Boolean) rVar.c.a(AbstractC2773w7.m4)).booleanValue()) {
                        com.google.android.gms.ads.internal.j.C.g.l(new C1996e6(this, 0));
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void u(I3 i3, C2093gF c2093gF, A9 a9) {
        if (c2093gF == null) {
            return;
        }
        if (a9.a(c2093gF.a) != -1) {
            i3.f(c2093gF, a9);
            return;
        }
        A9 a92 = (A9) ((Gu) this.c).get(c2093gF);
        if (a92 != null) {
            i3.f(c2093gF, a92);
        }
    }

    public void v() {
        C2172i6 c2172i6;
        synchronized (this.c) {
            if (((Context) this.e) != null && ((C2172i6) this.d) == null) {
                Ts ts = new Ts(this, 6);
                S4 s4 = new S4(this, 4);
                synchronized (this) {
                    c2172i6 = new C2172i6((Context) this.e, com.google.android.gms.ads.internal.j.C.t.o(), ts, s4);
                }
                this.d = c2172i6;
                c2172i6.c();
            }
        }
    }

    public void w(A9 a9) {
        I3 i3 = new I3(4);
        if (((AbstractC2330lu) this.b).isEmpty()) {
            u(i3, (C2093gF) this.e, a9);
            if (!Objects.equals((C2093gF) this.f, (C2093gF) this.e)) {
                u(i3, (C2093gF) this.f, a9);
            }
            if (!Objects.equals((C2093gF) this.d, (C2093gF) this.e) && !Objects.equals((C2093gF) this.d, (C2093gF) this.f)) {
                u(i3, (C2093gF) this.d, a9);
            }
        } else {
            for (int i = 0; i < ((AbstractC2330lu) this.b).size(); i++) {
                u(i3, (C2093gF) ((AbstractC2330lu) this.b).get(i), a9);
            }
            if (!((AbstractC2330lu) this.b).contains((C2093gF) this.d)) {
                u(i3, (C2093gF) this.d, a9);
            }
        }
        this.c = i3.m();
    }

    @Override // com.google.android.gms.ads.internal.d
    public void zzb() {
        if (((AtomicBoolean) this.f).get()) {
            ((Vg) this.a).onAdClicked();
        }
    }

    public C2084g6(Fi fi, C2326lq c2326lq, YF yf, String str, Xv xv) {
        this.a = fi;
        this.b = c2326lq;
        this.c = yf;
        this.d = str;
        this.f = xv;
    }

    public C2084g6(Lq lq, Object obj, String str, com.google.common.util.concurrent.e eVar, List list, com.google.common.util.concurrent.e eVar2) {
        this.f = lq;
        this.c = obj;
        this.a = str;
        this.b = eVar;
        this.d = list;
        this.e = eVar2;
    }

    public /* synthetic */ C2084g6(String str) {
        this.b = str;
    }
}
