package com.quizlet.infra.legacysyncengine.datasources;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes3.dex */
public class o extends c {
    public final com.quizlet.infra.legacysyncengine.net.c b;
    public final com.quizlet.infra.legacysyncengine.orm.query.a c;
    public io.reactivex.rxjava3.subjects.d d;
    public final f e = new f(this, 1);

    public o(com.quizlet.infra.legacysyncengine.net.c cVar, com.quizlet.infra.legacysyncengine.orm.query.a aVar) {
        this.b = cVar;
        this.c = aVar;
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final void a(b bVar) {
        ConcurrentHashMap.KeySetView keySetView = this.a;
        if (keySetView.remove(bVar) && this.d == null && keySetView.isEmpty()) {
            this.b.a(this.c, this.e);
        }
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final List b() {
        return this.b.d(this.c);
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final void c() {
        List listB;
        io.reactivex.rxjava3.subjects.d dVar;
        if (this.d != null && (listB = b()) != null && (dVar = this.d) != null) {
            dVar.b(listB);
        }
        super.c();
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final io.reactivex.rxjava3.core.i d() {
        return this.b.c(this.c, com.quizlet.infra.legacysyncengine.net.c.e);
    }

    @Override // com.quizlet.infra.legacysyncengine.datasources.c
    public final boolean e(b bVar) {
        boolean zE = super.e(bVar);
        if (zE && this.a.size() == 1 && this.d == null) {
            this.b.e(this.c, this.e);
        }
        return zE;
    }

    public final io.reactivex.rxjava3.core.i f() {
        if (this.d == null) {
            if (this.a.isEmpty()) {
                this.b.e(this.c, this.e);
            }
            this.d = io.reactivex.rxjava3.subjects.d.z();
            List listB = b();
            if (listB != null) {
                this.d.b(listB);
            }
        }
        return this.d.s(io.reactivex.rxjava3.android.schedulers.b.a());
    }

    public final void g() {
        if (this.d != null && this.a.isEmpty()) {
            this.b.a(this.c, this.e);
        }
        io.reactivex.rxjava3.subjects.d dVar = this.d;
        if (dVar != null) {
            dVar.onComplete();
            this.d = null;
        }
    }
}
