package io.reactivex.rxjava3.core;

/* loaded from: classes3.dex */
public final class m implements io.reactivex.rxjava3.disposables.b, Runnable {
    public final Runnable a;
    public final n b;
    public Thread c;

    public m(Runnable runnable, n nVar) {
        this.a = runnable;
        this.b = nVar;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        if (this.c == Thread.currentThread()) {
            n nVar = this.b;
            if (nVar instanceof io.reactivex.rxjava3.internal.schedulers.p) {
                io.reactivex.rxjava3.internal.schedulers.p pVar = (io.reactivex.rxjava3.internal.schedulers.p) nVar;
                if (pVar.b) {
                    return;
                }
                pVar.b = true;
                pVar.a.shutdown();
                return;
            }
        }
        this.b.dispose();
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.c = Thread.currentThread();
        try {
            this.a.run();
        } finally {
        }
    }
}
