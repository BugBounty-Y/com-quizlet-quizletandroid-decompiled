package androidx.work;

import androidx.compose.animation.d0;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.work.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class ThreadFactoryC1423d implements ThreadFactory {
    public final AtomicInteger a = new AtomicInteger(0);
    public final /* synthetic */ boolean b;

    public ThreadFactoryC1423d(boolean z) {
        this.b = z;
    }

    @Override // java.util.concurrent.ThreadFactory
    public final Thread newThread(Runnable runnable) {
        Intrinsics.checkNotNullParameter(runnable, "runnable");
        StringBuilder sbU = d0.u(this.b ? "WM.task-" : "androidx.work-");
        sbU.append(this.a.incrementAndGet());
        return new Thread(runnable, sbU.toString());
    }
}
