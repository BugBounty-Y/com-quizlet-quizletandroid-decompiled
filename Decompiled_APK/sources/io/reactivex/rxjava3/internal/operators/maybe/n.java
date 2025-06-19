package io.reactivex.rxjava3.internal.operators.maybe;

import com.google.android.gms.internal.mlkit_vision_barcode.z7;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes3.dex */
public final class n extends io.reactivex.rxjava3.internal.subscriptions.a implements io.reactivex.rxjava3.core.h {
    public final io.reactivex.rxjava3.core.f a;
    public final Object d;
    public final int f;
    public volatile boolean g;
    public long h;
    public final io.reactivex.rxjava3.disposables.a b = new io.reactivex.rxjava3.disposables.a();
    public final AtomicLong c = new AtomicLong();
    public final io.reactivex.rxjava3.internal.util.b e = new io.reactivex.rxjava3.internal.util.b();

    public n(io.reactivex.rxjava3.core.f fVar, int i, p pVar) {
        this.a = fVar;
        this.f = i;
        this.d = pVar;
    }

    @Override // io.reactivex.rxjava3.core.h
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        this.b.b(bVar);
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [io.reactivex.rxjava3.internal.operators.maybe.p, io.reactivex.rxjava3.operators.e, java.lang.Object] */
    public final void b() {
        io.reactivex.rxjava3.internal.util.e eVar;
        if (getAndIncrement() != 0) {
            return;
        }
        io.reactivex.rxjava3.core.f fVar = this.a;
        ?? r1 = this.d;
        long j = this.h;
        int iAddAndGet = 1;
        do {
            long j2 = this.c.get();
            while (true) {
                eVar = io.reactivex.rxjava3.internal.util.e.a;
                if (j == j2) {
                    break;
                }
                if (this.g) {
                    r1.clear();
                    return;
                }
                if (((Throwable) this.e.get()) != null) {
                    r1.clear();
                    this.e.f(this.a);
                    return;
                } else {
                    if (r1.g() == this.f) {
                        fVar.onComplete();
                        return;
                    }
                    Object objPoll = r1.poll();
                    if (objPoll == null) {
                        break;
                    } else if (objPoll != eVar) {
                        fVar.b(objPoll);
                        j++;
                    }
                }
            }
            if (j == j2) {
                if (((Throwable) this.e.get()) != null) {
                    r1.clear();
                    this.e.f(this.a);
                    return;
                } else {
                    while (r1.peek() == eVar) {
                        r1.c();
                    }
                    if (r1.g() == this.f) {
                        fVar.onComplete();
                        return;
                    }
                }
            }
            this.h = j;
            iAddAndGet = addAndGet(-iAddAndGet);
        } while (iAddAndGet != 0);
    }

    /* JADX WARN: Type inference failed for: r0v4, types: [io.reactivex.rxjava3.operators.e, java.lang.Object] */
    @Override // org.reactivestreams.b
    public final void cancel() {
        if (this.g) {
            return;
        }
        this.g = true;
        this.b.dispose();
        if (getAndIncrement() == 0) {
            this.d.clear();
        }
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [io.reactivex.rxjava3.operators.e, java.lang.Object] */
    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        this.d.clear();
    }

    @Override // org.reactivestreams.b
    public final void e(long j) {
        if (io.reactivex.rxjava3.internal.subscriptions.c.c(j)) {
            z7.f(this.c, j);
            b();
        }
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [io.reactivex.rxjava3.operators.e, java.lang.Object] */
    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return this.d.isEmpty();
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [io.reactivex.rxjava3.operators.e, java.lang.Object] */
    @Override // io.reactivex.rxjava3.core.h
    public final void onComplete() {
        this.d.offer(io.reactivex.rxjava3.internal.util.e.a);
        b();
    }

    /* JADX WARN: Type inference failed for: r0v1, types: [io.reactivex.rxjava3.operators.e, java.lang.Object] */
    @Override // io.reactivex.rxjava3.core.h
    public final void onError(Throwable th) {
        if (this.e.c(th)) {
            this.b.dispose();
            this.d.offer(io.reactivex.rxjava3.internal.util.e.a);
            b();
        }
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [io.reactivex.rxjava3.operators.e, java.lang.Object] */
    @Override // io.reactivex.rxjava3.core.h, io.reactivex.rxjava3.core.q, com.google.android.gms.tasks.d
    public final void onSuccess(Object obj) {
        this.d.offer(obj);
        b();
    }

    /* JADX WARN: Type inference failed for: r0v0, types: [io.reactivex.rxjava3.operators.e, java.lang.Object] */
    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        Object objPoll;
        do {
            objPoll = this.d.poll();
        } while (objPoll == io.reactivex.rxjava3.internal.util.e.a);
        return objPoll;
    }
}
