package androidx.arch.core.executor;

import com.google.firebase.crashlytics.internal.common.t;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes.dex */
public final class c implements ThreadFactory {
    public final /* synthetic */ int a;
    public final Number b;

    public c(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.b = new AtomicInteger(0);
                break;
            case 2:
                this.b = new AtomicInteger(0);
                break;
            default:
                this.b = new AtomicInteger(0);
                break;
        }
    }

    @Override // java.util.concurrent.ThreadFactory
    public final Thread newThread(Runnable runnable) {
        switch (this.a) {
            case 0:
                Thread thread = new Thread(runnable);
                thread.setName("arch_disk_io_" + ((AtomicInteger) this.b).getAndIncrement());
                return thread;
            case 1:
                Thread thread2 = new Thread(runnable);
                Locale locale = Locale.US;
                thread2.setName("CameraX-core_camera_" + ((AtomicInteger) this.b).getAndIncrement());
                return thread2;
            case 2:
                Thread thread3 = new Thread(runnable);
                Locale locale2 = Locale.US;
                thread3.setName("CameraX-camerax_io_" + ((AtomicInteger) this.b).getAndIncrement());
                return thread3;
            default:
                Thread threadNewThread = Executors.defaultThreadFactory().newThread(new t(runnable));
                threadNewThread.setName("awaitEvenIfOnMainThread task continuation executor" + ((AtomicLong) this.b).getAndIncrement());
                return threadNewThread;
        }
    }

    public c(AtomicLong atomicLong) {
        this.a = 3;
        this.b = atomicLong;
    }
}
