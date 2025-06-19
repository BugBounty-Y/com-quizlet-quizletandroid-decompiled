package io.reactivex.rxjava3.internal.operators.completable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import io.reactivex.rxjava3.core.q;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public final class e extends AtomicInteger implements io.reactivex.rxjava3.core.b, io.reactivex.rxjava3.disposables.b, q {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public io.reactivex.rxjava3.disposables.b d;

    public /* synthetic */ e(Object obj, io.reactivex.rxjava3.functions.a aVar, int i) {
        this.a = i;
        this.b = obj;
        this.c = aVar;
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        switch (this.a) {
            case 0:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.d, bVar)) {
                    this.d = bVar;
                    ((io.reactivex.rxjava3.core.b) this.b).a(this);
                    break;
                }
                break;
            case 1:
                ((io.reactivex.rxjava3.disposables.a) this.d).b(bVar);
                break;
            default:
                if (io.reactivex.rxjava3.internal.disposables.a.f(this.d, bVar)) {
                    this.d = bVar;
                    ((q) this.b).a(this);
                    break;
                }
                break;
        }
    }

    public void b() {
        switch (this.a) {
            case 0:
                if (compareAndSet(0, 1)) {
                    try {
                        ((io.reactivex.rxjava3.functions.a) this.c).run();
                        break;
                    } catch (Throwable th) {
                        x7.b(th);
                        C7.c(th);
                        return;
                    }
                }
                break;
            default:
                if (compareAndSet(0, 1)) {
                    try {
                        ((io.reactivex.rxjava3.functions.a) this.c).run();
                        break;
                    } catch (Throwable th2) {
                        x7.b(th2);
                        C7.c(th2);
                    }
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        switch (this.a) {
            case 0:
                this.d.dispose();
                b();
                break;
            case 1:
                ((io.reactivex.rxjava3.disposables.a) this.d).dispose();
                ((AtomicBoolean) this.c).set(true);
                break;
            default:
                this.d.dispose();
                b();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public void onComplete() {
        switch (this.a) {
            case 0:
                ((io.reactivex.rxjava3.core.b) this.b).onComplete();
                b();
                break;
            default:
                if (decrementAndGet() == 0) {
                    ((io.reactivex.rxjava3.core.b) this.b).onComplete();
                    break;
                }
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.b
    public final void onError(Throwable th) {
        switch (this.a) {
            case 0:
                ((io.reactivex.rxjava3.core.b) this.b).onError(th);
                b();
                break;
            case 1:
                ((io.reactivex.rxjava3.disposables.a) this.d).dispose();
                if (!((AtomicBoolean) this.c).compareAndSet(false, true)) {
                    C7.c(th);
                    break;
                } else {
                    ((io.reactivex.rxjava3.core.b) this.b).onError(th);
                    break;
                }
            default:
                ((q) this.b).onError(th);
                b();
                break;
        }
    }

    @Override // io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public void onSuccess(Object obj) {
        ((q) this.b).onSuccess(obj);
        b();
    }

    public e(io.reactivex.rxjava3.core.b bVar, AtomicBoolean atomicBoolean, io.reactivex.rxjava3.disposables.a aVar, int i) {
        this.a = 1;
        this.b = bVar;
        this.c = atomicBoolean;
        this.d = aVar;
        lazySet(i);
    }
}
