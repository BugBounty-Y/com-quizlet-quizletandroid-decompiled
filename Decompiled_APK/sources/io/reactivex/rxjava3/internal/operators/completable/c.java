package io.reactivex.rxjava3.internal.operators.completable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import com.quizlet.quizletandroid.ui.common.ads.C4636c;
import io.reactivex.rxjava3.core.p;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes3.dex */
public final class c extends io.reactivex.rxjava3.core.a {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ c(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // io.reactivex.rxjava3.core.a
    public final void g(io.reactivex.rxjava3.core.b bVar) {
        switch (this.a) {
            case 0:
                try {
                    Iterator it2 = ((List) this.b).iterator();
                    Objects.requireNonNull(it2, "The iterator returned is null");
                    b bVar2 = new b(bVar, it2);
                    bVar.a(bVar2.c);
                    bVar2.b();
                    break;
                } catch (Throwable th) {
                    x7.b(th);
                    io.reactivex.rxjava3.internal.disposables.b.b(th, bVar);
                    return;
                }
            case 1:
                d dVar = new d(bVar);
                bVar.a(dVar);
                try {
                    ((io.reactivex.rxjava3.core.c) this.b).e(dVar);
                    break;
                } catch (Throwable th2) {
                    x7.b(th2);
                    dVar.onError(th2);
                    return;
                }
            case 2:
                try {
                    Object obj = ((io.reactivex.rxjava3.functions.j) this.b).get();
                    Objects.requireNonNull(obj, "The completableSupplier returned a null CompletableSource");
                    ((io.reactivex.rxjava3.core.d) obj).b(bVar);
                    break;
                } catch (Throwable th3) {
                    x7.b(th3);
                    io.reactivex.rxjava3.internal.disposables.b.b(th3, bVar);
                    return;
                }
            case 3:
                io.reactivex.rxjava3.internal.disposables.b.b((Throwable) this.b, bVar);
                break;
            case 4:
                io.reactivex.rxjava3.disposables.d dVar2 = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
                bVar.a(dVar2);
                try {
                    ((Callable) this.b).call();
                    if (!dVar2.b()) {
                        bVar.onComplete();
                        break;
                    }
                } catch (Throwable th4) {
                    x7.b(th4);
                    if (dVar2.b()) {
                        C7.c(th4);
                        return;
                    } else {
                        bVar.onError(th4);
                        return;
                    }
                }
                break;
            case 5:
                io.reactivex.rxjava3.disposables.d dVar3 = new io.reactivex.rxjava3.disposables.d(io.reactivex.rxjava3.internal.functions.d.b, 0);
                bVar.a(dVar3);
                if (!dVar3.b()) {
                    try {
                        ((Runnable) this.b).run();
                        if (!dVar3.b()) {
                            bVar.onComplete();
                            break;
                        }
                    } catch (Throwable th5) {
                        x7.b(th5);
                        if (dVar3.b()) {
                            C7.c(th5);
                            return;
                        } else {
                            bVar.onError(th5);
                            return;
                        }
                    }
                }
                break;
            case 6:
                ((p) this.b).j(new C4636c(bVar, 10));
                break;
            case 7:
                ((io.reactivex.rxjava3.core.d) this.b).b(bVar);
                break;
            case 8:
                io.reactivex.rxjava3.disposables.a aVar = new io.reactivex.rxjava3.disposables.a();
                e eVar = new e(bVar, new AtomicBoolean(), aVar, ((io.reactivex.rxjava3.core.d[]) this.b).length + 1);
                bVar.a(eVar);
                for (io.reactivex.rxjava3.core.d dVar4 : (io.reactivex.rxjava3.core.d[]) this.b) {
                    if (aVar.b) {
                        break;
                    } else if (dVar4 == null) {
                        aVar.dispose();
                        eVar.onError(new NullPointerException("A completable source is null"));
                        break;
                    } else {
                        dVar4.b(eVar);
                    }
                }
                eVar.onComplete();
                break;
            default:
                ((io.reactivex.rxjava3.core.a) this.b).b(new com.quizlet.login.authentication.login.a(bVar, 20));
                break;
        }
    }
}
