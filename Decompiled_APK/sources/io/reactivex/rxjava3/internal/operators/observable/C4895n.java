package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.x7;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

/* renamed from: io.reactivex.rxjava3.internal.operators.observable.n, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4895n extends AtomicInteger implements io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public final io.reactivex.rxjava3.functions.h b;
    public final C4894m[] c;
    public Object[] d;
    public final io.reactivex.rxjava3.operators.g e;
    public volatile boolean f;
    public volatile boolean g;
    public final io.reactivex.rxjava3.internal.util.b h = new io.reactivex.rxjava3.internal.util.b();
    public int i;
    public int j;

    public C4895n(io.reactivex.rxjava3.core.l lVar, io.reactivex.rxjava3.functions.h hVar, int i, int i2) {
        this.a = lVar;
        this.b = hVar;
        this.d = new Object[i];
        C4894m[] c4894mArr = new C4894m[i];
        for (int i3 = 0; i3 < i; i3++) {
            c4894mArr[i3] = new C4894m(this, i3);
        }
        this.c = c4894mArr;
        this.e = new io.reactivex.rxjava3.operators.g(i2);
    }

    public final void a() {
        for (C4894m c4894m : this.c) {
            c4894m.getClass();
            io.reactivex.rxjava3.internal.disposables.a.a(c4894m);
        }
    }

    public final void b(io.reactivex.rxjava3.operators.g gVar) {
        synchronized (this) {
            this.d = null;
        }
        gVar.clear();
    }

    public final void c() {
        if (getAndIncrement() != 0) {
            return;
        }
        io.reactivex.rxjava3.operators.g gVar = this.e;
        io.reactivex.rxjava3.core.l lVar = this.a;
        int iAddAndGet = 1;
        while (!this.f) {
            if (this.h.get() != null) {
                a();
                b(gVar);
                this.h.g(lVar);
                return;
            }
            boolean z = this.g;
            Object[] objArr = (Object[]) gVar.poll();
            boolean z2 = objArr == null;
            if (z && z2) {
                b(gVar);
                this.h.g(lVar);
                return;
            }
            if (z2) {
                iAddAndGet = addAndGet(-iAddAndGet);
                if (iAddAndGet == 0) {
                    return;
                }
            } else {
                try {
                    Object objApply = this.b.apply(objArr);
                    Objects.requireNonNull(objApply, "The combiner returned a null value");
                    lVar.b(objApply);
                } catch (Throwable th) {
                    x7.b(th);
                    this.h.c(th);
                    a();
                    b(gVar);
                    this.h.g(lVar);
                    return;
                }
            }
        }
        b(gVar);
        this.h.d();
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.f) {
            return;
        }
        this.f = true;
        a();
        c();
    }
}
