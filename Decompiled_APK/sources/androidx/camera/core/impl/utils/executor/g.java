package androidx.camera.core.impl.utils.executor;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* loaded from: classes.dex */
public final class g implements Executor {
    public static volatile g c;
    public final /* synthetic */ int a;
    public final ExecutorService b;

    public g(ExecutorService executorService) {
        this.a = 1;
        this.b = executorService;
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        switch (this.a) {
            case 0:
                this.b.execute(runnable);
                break;
            default:
                this.b.execute(new j(runnable, 2));
                break;
        }
    }

    public g() {
        this.a = 0;
        this.b = Executors.newSingleThreadExecutor(new f(0));
    }
}
