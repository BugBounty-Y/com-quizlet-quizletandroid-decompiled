package androidx.core.provider;

import android.os.Handler;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;

/* loaded from: classes.dex */
public final class j implements Executor {
    public final /* synthetic */ int a;
    public final Handler b;

    public /* synthetic */ j(Handler handler, int i) {
        this.a = i;
        this.b = handler;
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
}
