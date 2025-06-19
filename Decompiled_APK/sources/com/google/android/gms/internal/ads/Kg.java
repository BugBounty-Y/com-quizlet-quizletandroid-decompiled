package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zze;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class Kg implements Xg, InterfaceC2015ei, Ph, InterfaceC2102gh, E5 {
    public final C2146hh a;
    public final Ch b;
    public final Vp c;
    public final ScheduledExecutorService d;
    public final Xv e;
    public ScheduledFuture g;
    public final String i;
    public final C1985dw f = new C1985dw();
    public final AtomicBoolean h = new AtomicBoolean();

    public Kg(C2146hh c2146hh, Vp vp, ScheduledExecutorService scheduledExecutorService, Xv xv, String str, Ch ch) {
        this.a = c2146hh;
        this.c = vp;
        this.d = scheduledExecutorService;
        this.e = xv;
        this.i = str;
        this.b = ch;
    }

    @Override // com.google.android.gms.internal.ads.E5
    public final void R0(D5 d5) {
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.wb)).booleanValue() && c() && d5.j && this.h.compareAndSet(false, true) && this.c.e != 3) {
            com.google.android.gms.ads.internal.util.A.l("Full screen 1px impression occurred");
            this.a.a();
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void a() {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void b() {
    }

    public final boolean c() {
        return this.i.equals("com.google.ads.mediation.admob.AdMobAdapter");
    }

    @Override // com.google.android.gms.internal.ads.Ph
    public final synchronized void d() {
        if (this.c.e == 4) {
            this.a.a();
            return;
        }
        C1985dw c1985dw = this.f;
        if (c1985dw.isDone()) {
            return;
        }
        ScheduledFuture scheduledFuture = this.g;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(true);
        }
        c1985dw.g(Boolean.TRUE);
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void f() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2015ei
    public final void i() {
    }

    @Override // com.google.android.gms.internal.ads.Ph
    public final void o() {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void q() {
        Vp vp = this.c;
        if (vp.e == 3) {
            return;
        }
        int i = vp.Y;
        if (i == 0 || i == 1) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.wb)).booleanValue() && c()) {
                return;
            }
            this.a.a();
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2102gh
    public final synchronized void r(zze zzeVar) {
        try {
            C1985dw c1985dw = this.f;
            if (c1985dw.isDone()) {
                return;
            }
            ScheduledFuture scheduledFuture = this.g;
            if (scheduledFuture != null) {
                scheduledFuture.cancel(true);
            }
            c1985dw.h(new Exception());
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void v(BinderC1966dc binderC1966dc, String str, String str2) {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void zze() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2015ei
    public final void zzi() {
        Vp vp = this.c;
        int i = vp.e;
        if (i == 3) {
            return;
        }
        if (i == 4) {
            this.b.a();
            return;
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.z1)).booleanValue() && vp.Y == 2) {
            int i2 = vp.q;
            if (i2 == 0) {
                this.a.a();
                return;
            }
            Os os = new Os(this, 15);
            C1985dw c1985dw = this.f;
            c1985dw.a(new Qv(0, c1985dw, os), this.e);
            this.g = this.d.schedule(new RunnableC1989e(this, 27), i2, TimeUnit.MILLISECONDS);
        }
    }
}
