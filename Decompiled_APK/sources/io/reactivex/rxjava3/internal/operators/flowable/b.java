package io.reactivex.rxjava3.internal.operators.flowable;

import com.google.android.gms.internal.ads.C2245jv;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.core.i;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.core.q;
import io.reactivex.rxjava3.core.r;
import io.reactivex.rxjava3.functions.j;
import io.reactivex.rxjava3.internal.operators.observable.C4883b;
import io.reactivex.rxjava3.internal.operators.observable.a0;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.Callable;

/* loaded from: classes3.dex */
public final class b extends p {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.core.p
    public final void k(q qVar) {
        io.reactivex.rxjava3.disposables.b bVar = io.reactivex.rxjava3.internal.disposables.b.a;
        Object obj = this.b;
        switch (this.a) {
            case 0:
                ((io.reactivex.rxjava3.core.e) obj).a(new a(qVar));
                return;
            case 1:
                ((io.reactivex.rxjava3.subjects.b) obj).c(new a0(qVar));
                return;
            case 2:
                ((i) obj).c(new C4883b(qVar, 3));
                return;
            case 3:
                io.reactivex.rxjava3.internal.operators.single.c cVar = new io.reactivex.rxjava3.internal.operators.single.c(qVar);
                qVar.a(cVar);
                try {
                    ((r) obj).j(cVar);
                    return;
                } catch (Throwable th) {
                    x7.b(th);
                    if (cVar.b(th)) {
                        return;
                    }
                    C7.c(th);
                    return;
                }
            case 4:
                try {
                    Object obj2 = ((j) obj).get();
                    Objects.requireNonNull(obj2, "The singleSupplier returned a null SingleSource");
                    ((p) obj2).j(qVar);
                    return;
                } catch (Throwable th2) {
                    x7.b(th2);
                    qVar.a(bVar);
                    qVar.onError(th2);
                    return;
                }
            case 5:
                try {
                    th = ((io.reactivex.rxjava3.internal.functions.c) obj).a;
                } catch (Throwable th3) {
                    th = th3;
                    x7.b(th);
                }
                if (th == null) {
                    throw io.reactivex.rxjava3.internal.util.c.a("Supplier returned a null Throwable.");
                }
                C2245jv c2245jv = io.reactivex.rxjava3.internal.util.c.a;
                qVar.a(bVar);
                qVar.onError(th);
                return;
            case 6:
                io.reactivex.rxjava3.disposables.d dVar = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
                qVar.a(dVar);
                if (dVar.b()) {
                    return;
                }
                try {
                    Object objCall = ((Callable) obj).call();
                    Objects.requireNonNull(objCall, "The callable returned a null value");
                    if (dVar.b()) {
                        return;
                    }
                    qVar.onSuccess(objCall);
                    return;
                } catch (Throwable th4) {
                    x7.b(th4);
                    if (dVar.b()) {
                        C7.c(th4);
                        return;
                    } else {
                        qVar.onError(th4);
                        return;
                    }
                }
            case 7:
                qVar.a(bVar);
                qVar.onSuccess(obj);
                return;
            default:
                p[] pVarArr = new p[8];
                try {
                    Iterator it2 = ((ArrayList) obj).iterator();
                    int i = 0;
                    while (it2.hasNext()) {
                        p pVar = (p) it2.next();
                        if (pVar == null) {
                            Throwable nullPointerException = new NullPointerException("One of the sources is null");
                            qVar.a(bVar);
                            qVar.onError(nullPointerException);
                            return;
                        } else {
                            if (i == pVarArr.length) {
                                pVarArr = (p[]) Arrays.copyOf(pVarArr, (i >> 2) + i);
                            }
                            int i2 = i + 1;
                            pVarArr[i] = pVar;
                            i = i2;
                        }
                    }
                    if (i == 0) {
                        Throwable noSuchElementException = new NoSuchElementException();
                        qVar.a(bVar);
                        qVar.onError(noSuchElementException);
                        return;
                    } else {
                        if (i == 1) {
                            pVarArr[0].j(new com.quizlet.remote.model.user.emailconfirmation.c(qVar, new com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c(this, 13)));
                            return;
                        }
                        io.reactivex.rxjava3.internal.operators.single.p pVar2 = new io.reactivex.rxjava3.internal.operators.single.p(i, qVar, com.quizlet.quizletandroid.ui.preview.dataclass.b.b);
                        qVar.a(pVar2);
                        for (int i3 = 0; i3 < i && !pVar2.b(); i3++) {
                            pVarArr[i3].j(pVar2.c[i3]);
                        }
                        return;
                    }
                } catch (Throwable th5) {
                    x7.b(th5);
                    qVar.a(bVar);
                    qVar.onError(th5);
                    return;
                }
        }
    }
}
