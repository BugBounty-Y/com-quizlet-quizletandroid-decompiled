package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.logging.Level;

/* loaded from: classes2.dex */
public abstract class Av extends Dv {
    public static final Wv o = new Wv(Av.class, 0);
    public AbstractC2071fu l;
    public final boolean m;
    public final boolean n;

    public Av(AbstractC2071fu abstractC2071fu, boolean z, boolean z2) {
        int size = abstractC2071fu.size();
        this.h = null;
        this.i = size;
        this.l = abstractC2071fu;
        this.m = z;
        this.n = z2;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final String e() {
        AbstractC2071fu abstractC2071fu = this.l;
        return abstractC2071fu != null ? "futures=".concat(abstractC2071fu.toString()) : super.e();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final void f() {
        AbstractC2071fu abstractC2071fu = this.l;
        t(1);
        if ((abstractC2071fu != null) && (this.a instanceof C2160hv)) {
            boolean zP = p();
            Pu puG = abstractC2071fu.g();
            while (puG.hasNext()) {
                ((Future) puG.next()).cancel(zP);
            }
        }
    }

    public abstract void t(int i);

    public final void u(AbstractC2071fu abstractC2071fu) {
        int iA = Dv.j.a(this);
        int i = 0;
        AbstractC1981ds.L("Less than 0 remaining futures", iA >= 0);
        if (iA == 0) {
            if (abstractC2071fu != null) {
                Pu puG = abstractC2071fu.g();
                while (puG.hasNext()) {
                    Future future = (Future) puG.next();
                    if (!future.isCancelled()) {
                        try {
                            x(i, AbstractC2543qs.d(future));
                        } catch (ExecutionException e) {
                            v(e.getCause());
                        } catch (Throwable th) {
                            v(th);
                        }
                    }
                    i++;
                }
            }
            this.h = null;
            y();
            t(2);
        }
    }

    public final void v(Throwable th) {
        th.getClass();
        if (this.m && !h(th)) {
            Set set = this.h;
            if (set == null) {
                Set setNewSetFromMap = Collections.newSetFromMap(new ConcurrentHashMap());
                setNewSetFromMap.getClass();
                if (!(this.a instanceof C2160hv)) {
                    Throwable thC = c();
                    Objects.requireNonNull(thC);
                    while (thC != null && setNewSetFromMap.add(thC)) {
                        thC = thC.getCause();
                    }
                }
                Dv.j.q(this, setNewSetFromMap);
                Set set2 = this.h;
                Objects.requireNonNull(set2);
                set = set2;
            }
            for (Throwable cause = th; cause != null; cause = cause.getCause()) {
                if (set.add(cause)) {
                }
            }
            o.a().logp(Level.SEVERE, "com.google.common.util.concurrent.AggregateFuture", "log", true != (th instanceof Error) ? "Got more than one input Future failure. Logging failures after the first" : "Input Future failed with Error", th);
            return;
        }
        boolean z = th instanceof Error;
        if (z) {
            o.a().logp(Level.SEVERE, "com.google.common.util.concurrent.AggregateFuture", "log", true != z ? "Got more than one input Future failure. Logging failures after the first" : "Input Future failed with Error", th);
        }
    }

    public final void w(int i, com.google.common.util.concurrent.e eVar) {
        try {
            if (eVar.isCancelled()) {
                this.l = null;
                cancel(false);
            } else {
                try {
                    x(i, AbstractC2543qs.d(eVar));
                } catch (ExecutionException e) {
                    v(e.getCause());
                } catch (Throwable th) {
                    v(th);
                }
            }
        } finally {
            u(null);
        }
    }

    public abstract void x(int i, Object obj);

    public abstract void y();

    public final void z() {
        Objects.requireNonNull(this.l);
        if (this.l.isEmpty()) {
            y();
            return;
        }
        Kv kv = Kv.a;
        if (this.m) {
            Pu puG = this.l.g();
            int i = 0;
            while (puG.hasNext()) {
                com.google.common.util.concurrent.e eVar = (com.google.common.util.concurrent.e) puG.next();
                int i2 = i + 1;
                if (eVar.isDone()) {
                    w(i, eVar);
                } else {
                    eVar.a(new Gk(this, i, eVar, 1), kv);
                }
                i = i2;
            }
            return;
        }
        AbstractC2071fu abstractC2071fu = this.l;
        AbstractC2071fu abstractC2071fu2 = true != this.n ? null : abstractC2071fu;
        RunnableC2793wl runnableC2793wl = new RunnableC2793wl(16, this, abstractC2071fu2);
        Pu puG2 = abstractC2071fu.g();
        while (puG2.hasNext()) {
            com.google.common.util.concurrent.e eVar2 = (com.google.common.util.concurrent.e) puG2.next();
            if (eVar2.isDone()) {
                u(abstractC2071fu2);
            } else {
                eVar2.a(runnableC2793wl, kv);
            }
        }
    }
}
