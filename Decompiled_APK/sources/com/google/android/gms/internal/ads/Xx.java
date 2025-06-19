package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class Xx {
    public static final Xx b;
    public final AtomicReference a = new AtomicReference(new C2634sy(new com.quizlet.data.repository.progress.b()));

    static {
        try {
            Xx xx = new Xx();
            xx.f(new Ix(Nx.class, new C2290kx(28)));
            b = xx;
        } catch (Exception e) {
            throw new zzgot(e);
        }
    }

    public final AbstractC2025es a(C2377my c2377my) {
        C2634sy c2634sy = (C2634sy) this.a.get();
        c2634sy.getClass();
        C2549qy c2549qy = new C2549qy(C2377my.class, c2377my.b);
        HashMap map = c2634sy.b;
        if (map.containsKey(c2549qy)) {
            return ((Gx) map.get(c2549qy)).b.f(c2377my);
        }
        throw new GeneralSecurityException(android.support.v4.media.session.a.B("No Key Parser for requested key type ", c2549qy.toString(), " available"));
    }

    public final AbstractC2547qw b(C2420ny c2420ny) throws GeneralSecurityException {
        C2634sy c2634sy = (C2634sy) this.a.get();
        c2634sy.getClass();
        C2549qy c2549qy = new C2549qy(C2420ny.class, c2420ny.a);
        HashMap map = c2634sy.d;
        if (map.containsKey(c2549qy)) {
            return ((Zx) map.get(c2549qy)).b.g(c2420ny);
        }
        throw new GeneralSecurityException(android.support.v4.media.session.a.B("No Parameters Parser for requested key type ", c2549qy.toString(), " available"));
    }

    public final InterfaceC2506py c(AbstractC2025es abstractC2025es) throws GeneralSecurityException {
        C2634sy c2634sy = (C2634sy) this.a.get();
        c2634sy.getClass();
        C2591ry c2591ry = new C2591ry(abstractC2025es.getClass(), C2377my.class);
        HashMap map = c2634sy.a;
        if (map.containsKey(c2591ry)) {
            return ((Ix) map.get(c2591ry)).b.a(abstractC2025es);
        }
        throw new GeneralSecurityException(android.support.v4.media.session.a.B("No Key serializer for ", c2591ry.toString(), " available"));
    }

    public final InterfaceC2506py d(AbstractC2547qw abstractC2547qw) throws GeneralSecurityException {
        C2634sy c2634sy = (C2634sy) this.a.get();
        c2634sy.getClass();
        C2591ry c2591ry = new C2591ry(abstractC2547qw.getClass(), C2420ny.class);
        HashMap map = c2634sy.c;
        if (map.containsKey(c2591ry)) {
            return ((C1944cy) map.get(c2591ry)).b.h(abstractC2547qw);
        }
        throw new GeneralSecurityException(android.support.v4.media.session.a.B("No Key Format serializer for ", c2591ry.toString(), " available"));
    }

    public final synchronized void e(Gx gx) {
        AtomicReference atomicReference = this.a;
        com.quizlet.data.repository.progress.b bVar = new com.quizlet.data.repository.progress.b((C2634sy) atomicReference.get());
        bVar.g(gx);
        atomicReference.set(new C2634sy(bVar));
    }

    public final synchronized void f(Ix ix) {
        AtomicReference atomicReference = this.a;
        com.quizlet.data.repository.progress.b bVar = new com.quizlet.data.repository.progress.b((C2634sy) atomicReference.get());
        bVar.h(ix);
        atomicReference.set(new C2634sy(bVar));
    }

    public final synchronized void g(Zx zx) {
        AtomicReference atomicReference = this.a;
        com.quizlet.data.repository.progress.b bVar = new com.quizlet.data.repository.progress.b((C2634sy) atomicReference.get());
        bVar.i(zx);
        atomicReference.set(new C2634sy(bVar));
    }

    public final synchronized void h(C1944cy c1944cy) {
        AtomicReference atomicReference = this.a;
        com.quizlet.data.repository.progress.b bVar = new com.quizlet.data.repository.progress.b((C2634sy) atomicReference.get());
        bVar.j(c1944cy);
        atomicReference.set(new C2634sy(bVar));
    }
}
