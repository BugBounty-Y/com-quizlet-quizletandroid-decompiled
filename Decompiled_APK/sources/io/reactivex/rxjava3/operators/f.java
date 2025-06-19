package io.reactivex.rxjava3.operators;

import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReferenceArray;

/* loaded from: classes3.dex */
public final class f extends AtomicReferenceArray implements d {
    public static final Integer f = Integer.getInteger("jctools.spsc.max.lookahead.step", 4096);
    public final int a;
    public final AtomicLong b;
    public long c;
    public final AtomicLong d;
    public final int e;

    public f(int i) {
        super(1 << (32 - Integer.numberOfLeadingZeros(i - 1)));
        this.a = length() - 1;
        this.b = new AtomicLong();
        this.d = new AtomicLong();
        this.e = Math.min(i / 4, f.intValue());
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final void clear() {
        while (true) {
            AtomicLong atomicLong = this.d;
            long j = atomicLong.get();
            int i = ((int) j) & this.a;
            Object obj = get(i);
            if (obj == null) {
                obj = null;
            } else {
                atomicLong.lazySet(j + 1);
                lazySet(i, null);
            }
            if (obj == null && isEmpty()) {
                return;
            }
        }
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean isEmpty() {
        return this.b.get() == this.d.get();
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final boolean offer(Object obj) {
        if (obj == null) {
            throw new NullPointerException("Null is not a valid element");
        }
        AtomicLong atomicLong = this.b;
        long j = atomicLong.get();
        int i = this.a;
        int i2 = ((int) j) & i;
        if (j >= this.c) {
            long j2 = this.e + j;
            if (get(i & ((int) j2)) == null) {
                this.c = j2;
            } else if (get(i2) != null) {
                return false;
            }
        }
        lazySet(i2, obj);
        atomicLong.lazySet(j + 1);
        return true;
    }

    @Override // io.reactivex.rxjava3.operators.e
    public final Object poll() {
        AtomicLong atomicLong = this.d;
        long j = atomicLong.get();
        int i = ((int) j) & this.a;
        Object obj = get(i);
        if (obj == null) {
            return null;
        }
        atomicLong.lazySet(j + 1);
        lazySet(i, null);
        return obj;
    }
}
