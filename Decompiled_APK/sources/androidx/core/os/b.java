package androidx.core.os;

import androidx.camera.camera2.internal.T;
import androidx.fragment.app.RunnableC1152u;
import androidx.transition.y;

/* loaded from: classes.dex */
public final class b {
    public boolean a;
    public boolean b;
    public Object c;

    public void a() {
        synchronized (this) {
            try {
                if (this.a) {
                    return;
                }
                this.a = true;
                this.b = true;
                T t = (T) this.c;
                if (t != null) {
                    try {
                        RunnableC1152u runnableC1152u = (RunnableC1152u) t.b;
                        if (runnableC1152u == null) {
                            ((y) t.c).cancel();
                            ((Runnable) t.d).run();
                        } else {
                            runnableC1152u.run();
                        }
                    } catch (Throwable th) {
                        synchronized (this) {
                            this.b = false;
                            notifyAll();
                            throw th;
                        }
                    }
                }
                synchronized (this) {
                    this.b = false;
                    notifyAll();
                }
            } finally {
            }
        }
    }
}
