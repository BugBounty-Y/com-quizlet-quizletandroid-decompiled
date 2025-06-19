package io.reactivex.rxjava3.internal.operators.maybe;

import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public final class m extends ConcurrentLinkedQueue implements p {
    public int a;
    public final AtomicInteger b = new AtomicInteger();

    @Override // io.reactivex.rxjava3.internal.operators.maybe.p
    public final void c() {
        poll();
    }

    @Override // io.reactivex.rxjava3.internal.operators.maybe.p
    public final int g() {
        return this.a;
    }

    @Override // java.util.concurrent.ConcurrentLinkedQueue, java.util.Queue, io.reactivex.rxjava3.operators.e
    public final boolean offer(Object obj) {
        this.b.getAndIncrement();
        return super.offer(obj);
    }

    @Override // java.util.concurrent.ConcurrentLinkedQueue, java.util.Queue, io.reactivex.rxjava3.operators.e
    public final Object poll() {
        Object objPoll = super.poll();
        if (objPoll != null) {
            this.a++;
        }
        return objPoll;
    }
}
