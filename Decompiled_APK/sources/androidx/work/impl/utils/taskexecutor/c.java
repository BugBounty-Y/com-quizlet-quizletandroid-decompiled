package androidx.work.impl.utils.taskexecutor;

import android.os.Handler;
import android.os.Looper;
import androidx.appcompat.app.ExecutorC0060p;
import java.util.concurrent.ExecutorService;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class c implements a {
    public final ExecutorC0060p a;
    public final AbstractC5040y b;
    public final Handler c = new Handler(Looper.getMainLooper());
    public final b d = new b(this, 0);

    public c(ExecutorService executorService) {
        ExecutorC0060p executorC0060p = new ExecutorC0060p(executorService);
        this.a = executorC0060p;
        this.b = E.p(executorC0060p);
    }
}
