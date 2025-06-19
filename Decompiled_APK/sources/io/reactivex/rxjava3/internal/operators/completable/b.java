package io.reactivex.rxjava3.internal.operators.completable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Iterator;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public final class b extends AtomicInteger implements io.reactivex.rxjava3.core.b {
    public final io.reactivex.rxjava3.core.b a;
    public final Iterator b;
    public final io.reactivex.rxjava3.disposables.d c = new io.reactivex.rxjava3.disposables.d(2);

    public b(io.reactivex.rxjava3.core.b bVar, Iterator it2) {
        this.a = bVar;
        this.b = it2;
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        io.reactivex.rxjava3.disposables.d dVar = this.c;
        dVar.getClass();
        io.reactivex.rxjava3.internal.disposables.a.c(dVar, bVar);
    }

    public final void b() {
        io.reactivex.rxjava3.core.b bVar = this.a;
        io.reactivex.rxjava3.disposables.d dVar = this.c;
        if (!dVar.b() && getAndIncrement() == 0) {
            Iterator it2 = this.b;
            while (!dVar.b()) {
                try {
                    if (!it2.hasNext()) {
                        bVar.onComplete();
                        return;
                    }
                    try {
                        Object next = it2.next();
                        Objects.requireNonNull(next, "The CompletableSource returned is null");
                        ((io.reactivex.rxjava3.core.d) next).b(this);
                        if (decrementAndGet() == 0) {
                            return;
                        }
                    } catch (Throwable th) {
                        x7.b(th);
                        bVar.onError(th);
                        return;
                    }
                } catch (Throwable th2) {
                    x7.b(th2);
                    bVar.onError(th2);
                    return;
                }
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onComplete() {
        b();
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onError(Throwable th) {
        this.a.onError(th);
    }
}
