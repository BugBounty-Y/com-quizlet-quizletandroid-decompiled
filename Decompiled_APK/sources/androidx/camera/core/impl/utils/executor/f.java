package androidx.camera.core.impl.utils.executor;

import java.util.concurrent.ThreadFactory;

/* loaded from: classes.dex */
public final class f implements ThreadFactory {
    public final /* synthetic */ int a;

    @Override // java.util.concurrent.ThreadFactory
    public final Thread newThread(Runnable runnable) {
        switch (this.a) {
            case 0:
                Thread thread = new Thread(runnable);
                thread.setPriority(10);
                thread.setName("CameraX-camerax_high_priority");
                return thread;
            case 1:
                return new androidx.core.provider.i(runnable);
            default:
                return new Thread(new j(runnable, 1), "glide-active-resources");
        }
    }
}
