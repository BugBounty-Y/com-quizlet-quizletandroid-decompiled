package com.bumptech.glide.load.engine;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public final class o implements com.bumptech.glide.util.pool.b {
    public static final com.google.android.material.shape.e w = new com.google.android.material.shape.e(6);
    public final n a;
    public final com.bumptech.glide.util.pool.e b;
    public final l c;
    public final com.quizlet.data.repository.course.membership.c d;
    public final com.google.android.material.shape.e e;
    public final l f;
    public final com.bumptech.glide.load.engine.executor.e g;
    public final com.bumptech.glide.load.engine.executor.e h;
    public final com.bumptech.glide.load.engine.executor.e i;
    public final AtomicInteger j;
    public p k;
    public boolean l;
    public boolean m;
    public v n;
    public int o;
    public boolean p;
    public GlideException q;
    public boolean r;
    public q s;
    public h t;
    public volatile boolean u;
    public boolean v;

    public o(com.bumptech.glide.load.engine.executor.e eVar, com.bumptech.glide.load.engine.executor.e eVar2, com.bumptech.glide.load.engine.executor.e eVar3, com.bumptech.glide.load.engine.executor.e eVar4, l lVar, l lVar2, com.quizlet.data.repository.course.membership.c cVar) {
        com.google.android.material.shape.e eVar5 = w;
        this.a = new n(new ArrayList(2), 0);
        this.b = new com.bumptech.glide.util.pool.e();
        this.j = new AtomicInteger();
        this.g = eVar;
        this.h = eVar2;
        this.i = eVar4;
        this.f = lVar;
        this.c = lVar2;
        this.d = cVar;
        this.e = eVar5;
    }

    public final synchronized void a(com.bumptech.glide.request.g gVar, androidx.camera.core.impl.utils.executor.a aVar) {
        try {
            this.b.a();
            n nVar = this.a;
            nVar.getClass();
            ((ArrayList) nVar.b).add(new m(gVar, aVar));
            if (this.p) {
                e(1);
                com.google.common.util.concurrent.d dVar = new com.google.common.util.concurrent.d(this, false, gVar, 11);
                aVar.getClass();
                com.bumptech.glide.util.m.j(dVar);
            } else if (this.r) {
                e(1);
                androidx.camera.core.impl.utils.futures.h hVar = new androidx.camera.core.impl.utils.futures.h(this, false, gVar, 11);
                aVar.getClass();
                com.bumptech.glide.util.m.j(hVar);
            } else {
                com.bumptech.glide.util.f.a("Cannot add callbacks to a cancelled EngineJob", !this.u);
            }
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // com.bumptech.glide.util.pool.b
    public final com.bumptech.glide.util.pool.e b() {
        return this.b;
    }

    public final void c() {
        if (f()) {
            return;
        }
        this.u = true;
        h hVar = this.t;
        hVar.z = true;
        f fVar = hVar.x;
        if (fVar != null) {
            fVar.cancel();
        }
        l lVar = this.f;
        p pVar = this.k;
        synchronized (lVar) {
            com.airbnb.lottie.network.c cVar = lVar.a;
            cVar.getClass();
            HashMap map = (HashMap) cVar.b;
            if (equals(map.get(pVar))) {
                map.remove(pVar);
            }
        }
    }

    public final void d() {
        q qVar;
        synchronized (this) {
            try {
                this.b.a();
                com.bumptech.glide.util.f.a("Not yet complete!", f());
                int iDecrementAndGet = this.j.decrementAndGet();
                com.bumptech.glide.util.f.a("Can't decrement below 0", iDecrementAndGet >= 0);
                if (iDecrementAndGet == 0) {
                    qVar = this.s;
                    g();
                } else {
                    qVar = null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (qVar != null) {
            qVar.d();
        }
    }

    public final synchronized void e(int i) {
        q qVar;
        com.bumptech.glide.util.f.a("Not yet complete!", f());
        if (this.j.getAndAdd(i) == 0 && (qVar = this.s) != null) {
            qVar.b();
        }
    }

    public final boolean f() {
        return this.r || this.p || this.u;
    }

    public final synchronized void g() {
        boolean zA;
        if (this.k == null) {
            throw new IllegalArgumentException();
        }
        ((ArrayList) this.a.b).clear();
        this.k = null;
        this.s = null;
        this.n = null;
        this.r = false;
        this.u = false;
        this.p = false;
        this.v = false;
        h hVar = this.t;
        androidx.camera.camera2.internal.compat.workaround.c cVar = hVar.g;
        synchronized (cVar) {
            cVar.a = true;
            zA = cVar.a();
        }
        if (zA) {
            hVar.j();
        }
        this.t = null;
        this.q = null;
        this.o = 0;
        this.d.o(this);
    }

    public final synchronized void h(com.bumptech.glide.request.g gVar) {
        try {
            this.b.a();
            n nVar = this.a;
            ((ArrayList) nVar.b).remove(new m(gVar, com.bumptech.glide.util.f.b));
            if (((ArrayList) this.a.b).isEmpty()) {
                c();
                if (this.p || this.r) {
                    if (this.j.get() == 0) {
                        g();
                    }
                }
            }
        } catch (Throwable th) {
            throw th;
        }
    }
}
