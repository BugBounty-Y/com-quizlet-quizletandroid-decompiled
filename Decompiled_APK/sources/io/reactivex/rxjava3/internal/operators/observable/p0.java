package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class p0 extends AtomicReference implements io.reactivex.rxjava3.core.l {
    public final q0 a;
    public final long b;
    public final int c;
    public volatile io.reactivex.rxjava3.operators.e d;
    public volatile boolean e;

    public p0(q0 q0Var, long j, int i) {
        this.a = q0Var;
        this.b = j;
        this.c = i;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.e(this, bVar)) {
            if (bVar instanceof io.reactivex.rxjava3.operators.a) {
                io.reactivex.rxjava3.operators.a aVar = (io.reactivex.rxjava3.operators.a) bVar;
                int iH = aVar.h(7);
                if (iH == 1) {
                    this.d = aVar;
                    this.e = true;
                    this.a.c();
                    return;
                } else if (iH == 2) {
                    this.d = aVar;
                    return;
                }
            }
            this.d = new io.reactivex.rxjava3.operators.g(this.c);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        io.reactivex.rxjava3.operators.e eVar = this.d;
        if (this.b != this.a.i || eVar == null) {
            return;
        }
        if (obj != null) {
            eVar.offer(obj);
        }
        this.a.c();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.b == this.a.i) {
            this.e = true;
            this.a.c();
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        q0 q0Var = this.a;
        q0Var.getClass();
        if (this.b != q0Var.i || !q0Var.d.b(th)) {
            C7.c(th);
            return;
        }
        q0Var.g.dispose();
        q0Var.e = true;
        this.e = true;
        q0Var.c();
    }
}
