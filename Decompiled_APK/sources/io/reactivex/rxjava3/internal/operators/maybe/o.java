package io.reactivex.rxjava3.internal.operators.maybe;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;

/* loaded from: classes3.dex */
public final class o extends AtomicReferenceArray implements p {
    public final AtomicInteger a;
    public int b;

    public o(int i) {
        super(i);
        this.a = new AtomicInteger();
    }

    @Override // io.reactivex.rxjava3.internal.operators.maybe.p
    public final void c() {
        int i = this.b;
        lazySet(i, null);
        this.b = i + 1;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        do {
            int i = this.b;
            Object obj = null;
            if (i != length()) {
                AtomicInteger atomicInteger = this.a;
                while (true) {
                    Object obj2 = get(i);
                    if (obj2 != null) {
                        this.b = i + 1;
                        lazySet(i, null);
                        obj = obj2;
                        break;
                    } else if (atomicInteger.get() == i) {
                        break;
                    }
                }
            }
            if (obj == null) {
                return;
            }
        } while (!isEmpty());
    }

    @Override // io.reactivex.rxjava3.internal.operators.maybe.p
    public final int g() {
        return this.b;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return this.b == this.a.get();
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean offer(Object obj) {
        Objects.requireNonNull(obj, "value is null");
        int andIncrement = this.a.getAndIncrement();
        if (andIncrement >= length()) {
            return false;
        }
        lazySet(andIncrement, obj);
        return true;
    }

    @Override // io.reactivex.rxjava3.internal.operators.maybe.p
    public final Object peek() {
        int i = this.b;
        if (i == length()) {
            return null;
        }
        return get(i);
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        int i = this.b;
        if (i == length()) {
            return null;
        }
        AtomicInteger atomicInteger = this.a;
        do {
            Object obj = get(i);
            if (obj != null) {
                this.b = i + 1;
                lazySet(i, null);
                return obj;
            }
        } while (atomicInteger.get() != i);
        return null;
    }
}
