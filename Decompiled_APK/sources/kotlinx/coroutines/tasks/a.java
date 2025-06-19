package kotlinx.coroutines.tasks;

import java.util.concurrent.Executor;

/* loaded from: classes3.dex */
public final class a implements Executor {
    public static final a a = new a();

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        runnable.run();
    }
}
