package io.reactivex.rxjava3.internal.schedulers;

/* loaded from: classes3.dex */
public final class o extends io.reactivex.rxjava3.core.o {
    public static final q b = new q("RxNewThreadScheduler", Math.max(1, Math.min(10, Integer.getInteger("rx3.newthread-priority", 5).intValue())), false);
    public final q a = b;

    @Override // io.reactivex.rxjava3.core.o
    public final io.reactivex.rxjava3.core.n a() {
        return new p(this.a);
    }
}
