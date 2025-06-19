package io.reactivex.rxjava3.internal.operators.flowable;

import com.quizlet.remote.model.school.h;

/* loaded from: classes3.dex */
public final class f extends io.reactivex.rxjava3.core.e {
    public final io.reactivex.rxjava3.core.e b;
    public final h c;

    public f(io.reactivex.rxjava3.core.e eVar, h hVar) {
        this.b = eVar;
        this.c = hVar;
    }

    @Override // io.reactivex.rxjava3.core.e
    public final void b(io.reactivex.rxjava3.core.f fVar) {
        e eVar = new e(fVar, this.c);
        fVar.c(eVar);
        this.b.a(eVar);
    }
}
