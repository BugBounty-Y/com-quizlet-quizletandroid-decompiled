package com.quizlet.billing.subscriptions;

import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.quizlet.upgrade.viewmodel.n;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.observable.N;

/* loaded from: classes2.dex */
public final class h implements InterfaceC1250k {
    public final com.quizlet.data.repository.achievements.h a;
    public final com.lyft.android.scissors.b b;
    public final i c;
    public final com.quizlet.billing.register.a d;
    public n e;
    public final io.reactivex.rxjava3.disposables.a f = new io.reactivex.rxjava3.disposables.a();
    public io.reactivex.rxjava3.internal.observers.e g;
    public final com.google.android.material.floatingactionbutton.c h;
    public final com.quizlet.billing.manager.f i;
    public final com.quizlet.data.repository.classfolder.e j;

    public h(com.quizlet.data.repository.achievements.h hVar, com.lyft.android.scissors.b bVar, com.quizlet.billing.manager.f fVar, i iVar, com.google.android.material.floatingactionbutton.c cVar, com.quizlet.billing.register.a aVar, com.quizlet.data.repository.classfolder.e eVar) {
        this.a = hVar;
        this.b = bVar;
        this.c = iVar;
        this.h = cVar;
        this.i = fVar;
        this.d = aVar;
        this.j = eVar;
    }

    public final void a(p pVar, long j, String str) {
        new io.reactivex.rxjava3.internal.operators.single.d(new io.reactivex.rxjava3.internal.operators.single.d(pVar.e(new androidx.camera.core.impl.utils.futures.e(this, j, str, 5)), new d(this, 1), 1), new a(this.f, 1), 1).i(new d(this, 2), new d(this, 0));
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onDestroy(J j) {
        io.reactivex.rxjava3.internal.observers.e eVar = this.g;
        if (eVar != null) {
            io.reactivex.rxjava3.internal.disposables.a.a(eVar);
            this.g = null;
        }
        this.f.d();
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStart(J j) {
        if (this.g == null) {
            this.g = new N(io.reactivex.rxjava3.core.i.n(com.quizlet.billing.manager.f.l), new f(this, 3), true).x(20).i(new c(0), new c(1));
        }
        com.quizlet.billing.manager.f fVar = this.i;
        boolean z = fVar.j;
        if (z) {
            if (!z) {
                throw new IllegalStateException("There is no pending purchase available. You must check hasPendingPurchase() first");
            }
            com.quizlet.billing.model.c cVar = fVar.i;
            a(cVar.e, cVar.a, cVar.d);
        }
    }
}
