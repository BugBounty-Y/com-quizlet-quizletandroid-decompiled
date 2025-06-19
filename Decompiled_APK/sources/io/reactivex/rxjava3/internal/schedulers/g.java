package io.reactivex.rxjava3.internal.schedulers;

import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes3.dex */
public final class g extends AtomicBoolean implements Runnable, io.reactivex.rxjava3.disposables.b {
    public final Runnable a;

    public g(Runnable runnable) {
        this.a = runnable;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        lazySet(true);
    }

    @Override // java.lang.Runnable
    public final void run() {
        if (get()) {
            return;
        }
        try {
            this.a.run();
        } finally {
        }
    }
}
