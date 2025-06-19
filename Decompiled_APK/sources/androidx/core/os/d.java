package androidx.core.os;

import android.os.Handler;
import android.os.Looper;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/* loaded from: classes.dex */
public final class d implements Executor {
    public final /* synthetic */ int a;
    public final Handler b;

    public d() {
        this.a = 1;
        this.b = new Handler(Looper.getMainLooper());
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        switch (this.a) {
            case 0:
                runnable.getClass();
                Handler handler = this.b;
                if (handler.post(runnable)) {
                    return;
                }
                throw new RejectedExecutionException(handler + " is shutting down");
            default:
                this.b.post(runnable);
                return;
        }
    }

    public d(Handler handler) {
        this.a = 0;
        this.b = handler;
    }
}
