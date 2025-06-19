package io.reactivex.rxjava3.internal.observers;

import io.reactivex.rxjava3.core.l;

/* loaded from: classes3.dex */
public abstract class f extends b {
    public final l a;
    public Object b;

    public f(l lVar) {
        this.a = lVar;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        lazySet(32);
        this.b = null;
    }

    public final void d(Object obj) {
        int i = get();
        if ((i & 54) != 0) {
            return;
        }
        l lVar = this.a;
        if (i == 8) {
            this.b = obj;
            lazySet(16);
            lVar.b(null);
        } else {
            lazySet(2);
            lVar.b(obj);
        }
        if (get() != 4) {
            lVar.onComplete();
        }
    }

    public final boolean e() {
        return get() == 4;
    }

    @Override // io.reactivex.rxjava3.operators.b
    public final int h(int i) {
        lazySet(8);
        return 2;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return get() != 16;
    }

    public void onSuccess(Object obj) {
        d(obj);
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        if (get() != 16) {
            return null;
        }
        Object obj = this.b;
        this.b = null;
        lazySet(32);
        return obj;
    }
}
