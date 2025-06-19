package io.reactivex.rxjava3.android.schedulers;

import android.os.Handler;
import android.os.Message;
import io.reactivex.rxjava3.core.n;
import java.util.concurrent.TimeUnit;

/* loaded from: classes3.dex */
public final class c extends n {
    public final Handler a;
    public volatile boolean b;

    public c(Handler handler) {
        this.a = handler;
    }

    @Override // io.reactivex.rxjava3.core.n
    public final io.reactivex.rxjava3.disposables.b b(Runnable runnable, long j, TimeUnit timeUnit) {
        if (timeUnit == null) {
            throw new NullPointerException("unit == null");
        }
        boolean z = this.b;
        io.reactivex.rxjava3.internal.disposables.b bVar = io.reactivex.rxjava3.internal.disposables.b.a;
        if (z) {
            return bVar;
        }
        Handler handler = this.a;
        d dVar = new d(handler, runnable);
        Message messageObtain = Message.obtain(handler, dVar);
        messageObtain.obj = this;
        messageObtain.setAsynchronous(true);
        this.a.sendMessageDelayed(messageObtain, timeUnit.toMillis(j));
        if (!this.b) {
            return dVar;
        }
        this.a.removeCallbacks(dVar);
        return bVar;
    }

    @Override // io.reactivex.rxjava3.disposables.b
    public final void dispose() {
        this.b = true;
        this.a.removeCallbacksAndMessages(this);
    }
}
