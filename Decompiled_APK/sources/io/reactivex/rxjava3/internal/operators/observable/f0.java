package io.reactivex.rxjava3.internal.operators.observable;

/* loaded from: classes3.dex */
public final class f0 extends io.reactivex.rxjava3.internal.observers.b {
    public final io.reactivex.rxjava3.core.l a;
    public final long b;
    public long c;
    public boolean d;

    public f0(io.reactivex.rxjava3.core.l lVar, long j, long j2) {
        this.a = lVar;
        this.c = j;
        this.b = j2;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        this.c = this.b;
        lazySet(1);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        set(1);
    }

    @Override // io.reactivex.rxjava3.operators.b
    public final int h(int i) {
        this.d = true;
        return 1;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return this.c == this.b;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        long j = this.c;
        if (j != this.b) {
            this.c = 1 + j;
            return Integer.valueOf((int) j);
        }
        lazySet(1);
        return null;
    }
}
