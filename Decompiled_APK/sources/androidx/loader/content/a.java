package androidx.loader.content;

import android.os.Handler;
import android.os.Looper;
import androidx.camera.core.impl.utils.futures.h;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final class a implements Runnable {
    public static Handler f;
    public final /* synthetic */ b e;
    public volatile int b = 1;
    public final AtomicBoolean c = new AtomicBoolean();
    public final AtomicBoolean d = new AtomicBoolean();
    public final d a = new d(this, new androidx.camera.core.impl.utils.executor.c(this, 1));

    public a(b bVar) {
        this.e = bVar;
    }

    public final void a(Object obj) {
        Handler handler;
        synchronized (a.class) {
            try {
                if (f == null) {
                    f = new Handler(Looper.getMainLooper());
                }
                handler = f;
            } catch (Throwable th) {
                throw th;
            }
        }
        handler.post(new h(this, false, obj, 5));
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.e.f();
    }
}
