package io.reactivex.rxjava3.internal.functions;

import io.reactivex.rxjava3.functions.h;
import io.reactivex.rxjava3.functions.j;
import java.util.concurrent.Callable;

/* loaded from: classes3.dex */
public final class c implements Callable, j, h {
    public final Throwable a;

    public c(Throwable th) {
        this.a = th;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public final Object apply(Object obj) {
        return this.a;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() {
        return this.a;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        return this.a;
    }
}
