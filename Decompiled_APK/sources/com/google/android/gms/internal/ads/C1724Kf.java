package com.google.android.gms.internal.ads;

import android.content.Context;
import java.lang.ref.WeakReference;
import java.nio.charset.Charset;
import java.util.HashSet;
import java.util.Iterator;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Kf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1724Kf implements E5, InterfaceC2231jh, com.google.android.gms.ads.internal.overlay.j, InterfaceC2189ih {
    public final C1700Gf a;
    public final C1706Hf b;
    public final C2525qa d;
    public final Executor e;
    public final com.google.android.gms.common.util.a f;
    public final HashSet c = new HashSet();
    public final AtomicBoolean g = new AtomicBoolean(false);
    public final C1718Jf h = new C1718Jf();
    public boolean i = false;
    public WeakReference j = new WeakReference(this);

    public C1724Kf(C2482pa c2482pa, C1706Hf c1706Hf, Executor executor, C1700Gf c1700Gf, com.google.android.gms.common.util.a aVar) {
        this.a = c1700Gf;
        Charset charset = AbstractC2224ja.a;
        c2482pa.a();
        this.d = new C2525qa(0, c2482pa.b);
        this.b = c1706Hf;
        this.e = executor;
        this.f = aVar;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final synchronized void E(Context context) {
        this.h.b = false;
        a();
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void I3() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2189ih
    public final synchronized void K() {
        if (this.g.compareAndSet(false, true)) {
            C1700Gf c1700Gf = this.a;
            C1694Ff c1694Ff = c1700Gf.e;
            C2482pa c2482pa = c1700Gf.b;
            c2482pa.a();
            com.google.common.util.concurrent.e eVar = c2482pa.b;
            C2439oa c2439oa = new C2439oa(0, "/updateActiveView", c1694Ff);
            C2227jd c2227jd = AbstractC2270kd.g;
            c2482pa.b = AbstractC2025es.N(eVar, c2439oa, c2227jd);
            C1694Ff c1694Ff2 = c1700Gf.f;
            c2482pa.a();
            c2482pa.b = AbstractC2025es.N(c2482pa.b, new C2439oa(0, "/untrackActiveViewUnit", c1694Ff2), c2227jd);
            c1700Gf.d = this;
            a();
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void L2() {
    }

    @Override // com.google.android.gms.internal.ads.E5
    public final synchronized void R0(D5 d5) {
        C1718Jf c1718Jf = this.h;
        c1718Jf.a = d5.j;
        c1718Jf.e = d5;
        a();
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void X(int i) {
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void Y3() {
        this.h.b = true;
        a();
    }

    public final synchronized void a() {
        try {
            if (this.j.get() == null) {
                synchronized (this) {
                    b();
                    this.i = true;
                }
                return;
            }
            if (this.i || !this.g.get()) {
                return;
            }
            try {
                C1718Jf c1718Jf = this.h;
                c1718Jf.c = this.f.elapsedRealtime();
                JSONObject jSONObjectC = this.b.c(c1718Jf);
                Iterator it2 = this.c.iterator();
                while (it2.hasNext()) {
                    this.e.execute(new RunnableC1712If(jSONObjectC, (InterfaceC2529qe) it2.next()));
                }
                C2525qa c2525qa = this.d;
                c2525qa.getClass();
                C2439oa c2439oa = new C2439oa(1, c2525qa, jSONObjectC);
                C2227jd c2227jd = AbstractC2270kd.g;
                C2846xv c2846xvN = AbstractC2025es.N(c2525qa.b, c2439oa, c2227jd);
                c2846xvN.a(new Qv(0, c2846xvN, new Ew("ActiveViewListener.callActiveViewJs", 3)), c2227jd);
                return;
            } catch (Exception unused) {
                com.google.android.gms.ads.internal.util.A.m();
                return;
            }
        } catch (Throwable th) {
            throw th;
        }
        throw th;
    }

    public final void b() {
        Iterator it2 = this.c.iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            String str = "/untrackActiveViewUnit";
            String str2 = "/updateActiveView";
            C1700Gf c1700Gf = this.a;
            if (!zHasNext) {
                C1694Ff c1694Ff = c1700Gf.e;
                C2482pa c2482pa = c1700Gf.b;
                com.google.common.util.concurrent.e eVar = c2482pa.b;
                C2353ma c2353ma = new C2353ma(0, str2, c1694Ff);
                C2227jd c2227jd = AbstractC2270kd.g;
                C2889yv c2889yvL = AbstractC2025es.L(eVar, c2353ma, c2227jd);
                c2482pa.b = c2889yvL;
                c2482pa.b = AbstractC2025es.L(c2889yvL, new C2353ma(0, str, c1700Gf.f), c2227jd);
                return;
            }
            InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) it2.next();
            interfaceC2529qe.F0("/updateActiveView", c1700Gf.e);
            interfaceC2529qe.F0("/untrackActiveViewUnit", c1700Gf.f);
        }
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final void f3() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final synchronized void j(Context context) {
        this.h.d = "u";
        a();
        b();
        this.i = true;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final synchronized void o(Context context) {
        this.h.b = true;
        a();
    }

    @Override // com.google.android.gms.ads.internal.overlay.j
    public final synchronized void v3() {
        this.h.b = false;
        a();
    }
}
