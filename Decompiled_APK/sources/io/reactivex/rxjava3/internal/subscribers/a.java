package io.reactivex.rxjava3.internal.subscribers;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.z7;
import io.reactivex.rxjava3.core.f;
import io.reactivex.rxjava3.internal.operators.completable.k;
import io.reactivex.rxjava3.internal.subscriptions.c;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.reactivestreams.b;

/* loaded from: classes3.dex */
public final class a extends AtomicInteger implements f, b {
    public final k a;
    public final io.reactivex.rxjava3.internal.util.b b = new io.reactivex.rxjava3.internal.util.b();
    public final AtomicLong c = new AtomicLong();
    public final AtomicReference d = new AtomicReference();
    public final AtomicBoolean e = new AtomicBoolean();
    public volatile boolean f;

    public a(k kVar) {
        this.a = kVar;
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void b(Object obj) {
        if (get() == 0 && compareAndSet(0, 1)) {
            k kVar = this.a;
            kVar.b(obj);
            if (decrementAndGet() == 0) {
                return;
            }
            this.b.f(kVar);
        }
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void c(b bVar) {
        if (!this.e.compareAndSet(false, true)) {
            bVar.cancel();
            cancel();
            onError(new IllegalStateException("§2.12 violated: onSubscribe must be called at most once"));
            return;
        }
        this.a.c(this);
        AtomicReference atomicReference = this.d;
        AtomicLong atomicLong = this.c;
        if (c.b(atomicReference, bVar)) {
            long andSet = atomicLong.getAndSet(0L);
            if (andSet != 0) {
                bVar.e(andSet);
            }
        }
    }

    @Override // org.reactivestreams.b
    public final void cancel() {
        if (this.f) {
            return;
        }
        c.a(this.d);
    }

    @Override // org.reactivestreams.b
    public final void e(long j) {
        if (j <= 0) {
            cancel();
            onError(new IllegalArgumentException(d0.n(j, "§3.9 violated: positive request amount required but it was ")));
            return;
        }
        AtomicReference atomicReference = this.d;
        AtomicLong atomicLong = this.c;
        b bVar = (b) atomicReference.get();
        if (bVar != null) {
            bVar.e(j);
            return;
        }
        if (c.c(j)) {
            z7.f(atomicLong, j);
            b bVar2 = (b) atomicReference.get();
            if (bVar2 != null) {
                long andSet = atomicLong.getAndSet(0L);
                if (andSet != 0) {
                    bVar2.e(andSet);
                }
            }
        }
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void onComplete() {
        this.f = true;
        k kVar = this.a;
        io.reactivex.rxjava3.internal.util.b bVar = this.b;
        if (getAndIncrement() == 0) {
            bVar.f(kVar);
        }
    }

    @Override // io.reactivex.rxjava3.core.f
    public final void onError(Throwable th) {
        this.f = true;
        k kVar = this.a;
        io.reactivex.rxjava3.internal.util.b bVar = this.b;
        if (bVar.c(th) && getAndIncrement() == 0) {
            bVar.f(kVar);
        }
    }
}
