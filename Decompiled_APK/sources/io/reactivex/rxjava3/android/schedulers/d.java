package io.reactivex.rxjava3.android.schedulers;

import android.os.Handler;
import com.google.android.gms.internal.mlkit_vision_barcode.C7;

/* loaded from: classes3.dex */
public final class d implements Runnable, io.reactivex.rxjava3.disposables.b {
    public final Handler a;
    public final Runnable b;

    public d(Handler handler, Runnable runnable) {
        this.a = handler;
        this.b = runnable;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.a.removeCallbacks(this);
    }

    @Override // java.lang.Runnable
    public final void run() {
        try {
            this.b.run();
        } catch (Throwable th) {
            C7.c(th);
        }
    }
}
