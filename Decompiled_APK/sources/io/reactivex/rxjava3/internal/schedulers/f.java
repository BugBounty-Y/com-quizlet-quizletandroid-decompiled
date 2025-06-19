package io.reactivex.rxjava3.internal.schedulers;

import com.google.android.gms.internal.mlkit_vision_barcode.C7;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes3.dex */
public final class f extends AtomicReference implements Runnable, io.reactivex.rxjava3.disposables.b {
    public final io.reactivex.rxjava3.disposables.d a;
    public final io.reactivex.rxjava3.disposables.d b;

    public f(Runnable runnable) {
        super(runnable);
        this.a = new io.reactivex.rxjava3.disposables.d(2);
        this.b = new io.reactivex.rxjava3.disposables.d(2);
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (getAndSet(null) != null) {
            io.reactivex.rxjava3.disposables.d dVar = this.a;
            dVar.getClass();
            io.reactivex.rxjava3.internal.disposables.a.a(dVar);
            io.reactivex.rxjava3.disposables.d dVar2 = this.b;
            dVar2.getClass();
            io.reactivex.rxjava3.internal.disposables.a.a(dVar2);
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        io.reactivex.rxjava3.disposables.d dVar = this.b;
        io.reactivex.rxjava3.disposables.d dVar2 = this.a;
        io.reactivex.rxjava3.internal.disposables.a aVar = io.reactivex.rxjava3.internal.disposables.a.a;
        Runnable runnable = (Runnable) get();
        if (runnable != null) {
            try {
                try {
                    runnable.run();
                } finally {
                    lazySet(null);
                    dVar2.lazySet(aVar);
                    dVar.lazySet(aVar);
                }
            } catch (Throwable th) {
                C7.c(th);
                throw th;
            }
        }
    }
}
