package io.reactivex.rxjava3.internal.operators.observable;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;

/* loaded from: classes3.dex */
public final class r0 implements io.reactivex.rxjava3.core.l, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.core.l a;
    public boolean b;
    public io.reactivex.rxjava3.disposables.b c;
    public long d = 1;

    public r0(io.reactivex.rxjava3.core.l lVar) {
        this.a = lVar;
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void a(io.reactivex.rxjava3.disposables.b bVar) {
        if (io.reactivex.rxjava3.internal.disposables.a.f(this.c, bVar)) {
            this.c = bVar;
            long j = this.d;
            io.reactivex.rxjava3.core.l lVar = this.a;
            if (j != 0) {
                lVar.a(this);
                return;
            }
            this.b = true;
            bVar.dispose();
            io.reactivex.rxjava3.internal.disposables.b.a(lVar);
        }
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void b(Object obj) {
        if (this.b) {
            return;
        }
        long j = this.d;
        long j2 = j - 1;
        this.d = j2;
        if (j > 0) {
            boolean z = j2 == 0;
            this.a.b(obj);
            if (z) {
                onComplete();
            }
        }
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.c.dispose();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onComplete() {
        if (this.b) {
            return;
        }
        this.b = true;
        this.c.dispose();
        this.a.onComplete();
    }

    @Override // io.reactivex.rxjava3.core.l
    public final void onError(Throwable th) {
        if (this.b) {
            C7.c(th);
            return;
        }
        this.b = true;
        this.c.dispose();
        this.a.onError(th);
    }
}
