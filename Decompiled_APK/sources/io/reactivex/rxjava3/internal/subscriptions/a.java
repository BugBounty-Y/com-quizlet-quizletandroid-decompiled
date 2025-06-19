package io.reactivex.rxjava3.internal.subscriptions;

import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes3.dex */
public abstract class a extends AtomicInteger implements io.reactivex.rxjava3.operators.b, org.reactivestreams.b {
    @Override // io.reactivex.rxjava3.operators.e
    public final boolean offer(Object obj) {
        throw new UnsupportedOperationException("Should not be called!");
    }
}
