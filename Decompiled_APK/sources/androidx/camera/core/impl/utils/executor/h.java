package androidx.camera.core.impl.utils.executor;

import android.os.Looper;
import com.google.android.gms.internal.ads.Ls;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/* loaded from: classes.dex */
public final class h implements Executor {
    public static volatile h c;
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ h(Ls ls) {
        this.a = 1;
        this.b = ls;
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        switch (this.a) {
            case 0:
                ((ExecutorService) this.b).execute(runnable);
                break;
            case 1:
                ((Ls) this.b).post(runnable);
                break;
            default:
                ((Ls) this.b).post(runnable);
                break;
        }
    }

    public h(int i) {
        this.a = i;
        switch (i) {
            case 2:
                Ls ls = new Ls(Looper.getMainLooper(), 6, false);
                Looper.getMainLooper();
                this.b = ls;
                break;
            default:
                this.b = Executors.newFixedThreadPool(2, new androidx.arch.core.executor.c(2));
                break;
        }
    }
}
