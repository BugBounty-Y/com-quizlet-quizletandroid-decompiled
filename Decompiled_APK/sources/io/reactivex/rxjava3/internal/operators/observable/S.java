package io.reactivex.rxjava3.internal.operators.observable;

import java.util.Iterator;
import java.util.Objects;

/* loaded from: classes3.dex */
public final class S extends io.reactivex.rxjava3.internal.observers.c {
    public final io.reactivex.rxjava3.core.l a;
    public final Iterator b;
    public volatile boolean c;
    public boolean d;
    public boolean e;
    public boolean f;

    public S(io.reactivex.rxjava3.core.l lVar, Iterator it2) {
        this.a = lVar;
        this.b = it2;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        this.e = true;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.c = true;
    }

    @Override // io.reactivex.rxjava3.operators.b
    public final int h(int i) {
        this.d = true;
        return 1;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return this.e;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        if (this.e) {
            return null;
        }
        boolean z = this.f;
        Iterator it2 = this.b;
        if (!z) {
            this.f = true;
        } else if (!it2.hasNext()) {
            this.e = true;
            return null;
        }
        Object next = it2.next();
        Objects.requireNonNull(next, "The iterator returned a null value");
        return next;
    }
}
