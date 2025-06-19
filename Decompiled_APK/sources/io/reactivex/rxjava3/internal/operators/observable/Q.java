package io.reactivex.rxjava3.internal.operators.observable;

import java.util.Objects;

/* loaded from: classes3.dex */
public final class Q extends io.reactivex.rxjava3.internal.observers.c {
    public final io.reactivex.rxjava3.core.l a;
    public final Object[] b;
    public int c;
    public boolean d;
    public volatile boolean e;

    public Q(io.reactivex.rxjava3.core.l lVar, Object[] objArr) {
        this.a = lVar;
        this.b = objArr;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        this.c = this.b.length;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.e = true;
    }

    @Override // io.reactivex.rxjava3.operators.b
    public final int h(int i) {
        this.d = true;
        return 1;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return this.c == this.b.length;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        int i = this.c;
        Object[] objArr = this.b;
        if (i == objArr.length) {
            return null;
        }
        this.c = i + 1;
        Object obj = objArr[i];
        Objects.requireNonNull(obj, "The array element is null");
        return obj;
    }
}
