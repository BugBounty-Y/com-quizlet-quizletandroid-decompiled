package io.reactivex.rxjava3.internal.operators.completable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.ktor.utils.io.A;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.exceptions.CompositeException;
import io.reactivex.rxjava3.internal.operators.single.o;

/* loaded from: classes3.dex */
public final class m extends p {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public final Object d;

    public /* synthetic */ m(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.c = obj;
        this.b = obj3;
        this.d = obj2;
    }

    @Override // io.reactivex.rxjava3.core.p
    public final void k(q qVar) {
        switch (this.a) {
            case 0:
                ((io.reactivex.rxjava3.core.a) this.c).b(new com.quizlet.remote.model.school.h(this, qVar));
                break;
            case 1:
                ((io.reactivex.rxjava3.core.i) this.c).c(new io.reactivex.rxjava3.internal.observers.g(qVar, (io.reactivex.rxjava3.functions.b) this.d, this.b, 1));
                break;
            case 2:
                ((p) this.c).j(new A(this, qVar));
                break;
            default:
                io.reactivex.rxjava3.internal.disposables.b bVar = io.reactivex.rxjava3.internal.disposables.b.a;
                com.quizlet.billing.manager.b bVar2 = (com.quizlet.billing.manager.b) this.b;
                try {
                    Object obj = ((com.quizlet.data.repository.classfolder.b) this.c).get();
                    try {
                        ((p) ((com.quizlet.data.repository.searchexplanations.c) this.d).apply(obj)).j(new o(qVar, obj, bVar2));
                        break;
                    } catch (Throwable th) {
                        th = th;
                        x7.b(th);
                        try {
                            bVar2.accept(obj);
                        } catch (Throwable th2) {
                            x7.b(th2);
                            th = new CompositeException(th, th2);
                        }
                        qVar.a(bVar);
                        qVar.onError(th);
                        return;
                    }
                } catch (Throwable th3) {
                    x7.b(th3);
                    qVar.a(bVar);
                    qVar.onError(th3);
                }
        }
    }

    public m(io.reactivex.rxjava3.core.i iVar, Object obj, io.reactivex.rxjava3.functions.b bVar) {
        this.a = 1;
        this.c = iVar;
        this.b = obj;
        this.d = bVar;
    }
}
