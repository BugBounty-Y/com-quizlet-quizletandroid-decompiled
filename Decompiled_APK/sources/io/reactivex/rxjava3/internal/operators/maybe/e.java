package io.reactivex.rxjava3.internal.operators.maybe;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.internal.operators.observable.C4883b;

/* loaded from: classes3.dex */
public final class e extends io.reactivex.rxjava3.core.g {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ e(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.core.g
    public final void f(io.reactivex.rxjava3.core.h hVar) {
        io.reactivex.rxjava3.disposables.b bVar;
        switch (this.a) {
            case 0:
                d dVar = new d(hVar);
                hVar.a(dVar);
                try {
                    ((com.google.firebase.tracing.a) this.b).c(dVar);
                    return;
                } catch (Throwable th) {
                    x7.b(th);
                    Object obj = dVar.get();
                    io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
                    if (obj == aVar || (bVar = (io.reactivex.rxjava3.disposables.b) dVar.getAndSet(aVar)) == aVar) {
                        C7.c(th);
                        return;
                    }
                    try {
                        ((io.reactivex.rxjava3.core.h) dVar.b).onError(th);
                        if (bVar != null) {
                            return;
                        } else {
                            return;
                        }
                    } finally {
                        if (bVar != null) {
                            bVar.dispose();
                        }
                    }
                }
            case 1:
                try {
                    ((io.reactivex.rxjava3.core.g) ((com.quizlet.data.repository.classfolder.b) this.b).get()).e(hVar);
                    return;
                } catch (Throwable th2) {
                    x7.b(th2);
                    hVar.a(io.reactivex.rxjava3.internal.disposables.b.a);
                    hVar.onError(th2);
                    return;
                }
            case 2:
                hVar.a(io.reactivex.rxjava3.internal.disposables.b.a);
                hVar.onError((Throwable) this.b);
                return;
            case 3:
                ((io.reactivex.rxjava3.core.p) this.b).j(new k(hVar, 0));
                return;
            default:
                ((io.reactivex.rxjava3.core.i) this.b).c(new C4883b(hVar, 2));
                return;
        }
    }
}
