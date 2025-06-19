package androidx.compose.ui.platform;

import android.os.Handler;
import android.view.Choreographer;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.collections.C4927s;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.AbstractC5040y;

/* loaded from: classes.dex */
public final class Z extends AbstractC5040y {
    public static final kotlin.u l = kotlin.l.b(O.h);
    public static final androidx.camera.core.impl.utils.executor.b m = new androidx.camera.core.impl.utils.executor.b(1);
    public final Choreographer b;
    public final Handler c;
    public boolean h;
    public boolean i;
    public final C0933b0 k;
    public final Object d = new Object();
    public final C4927s e = new C4927s();
    public ArrayList f = new ArrayList();
    public ArrayList g = new ArrayList();
    public final Y j = new Y(this);

    public Z(Choreographer choreographer, Handler handler) {
        this.b = choreographer;
        this.c = handler;
        this.k = new C0933b0(choreographer, this);
    }

    public static final void k0(Z z) {
        Runnable runnable;
        boolean z2;
        do {
            synchronized (z.d) {
                C4927s c4927s = z.e;
                runnable = (Runnable) (c4927s.isEmpty() ? null : c4927s.removeFirst());
            }
            while (runnable != null) {
                runnable.run();
                synchronized (z.d) {
                    C4927s c4927s2 = z.e;
                    runnable = (Runnable) (c4927s2.isEmpty() ? null : c4927s2.removeFirst());
                }
            }
            synchronized (z.d) {
                if (z.e.isEmpty()) {
                    z2 = false;
                    z.h = false;
                } else {
                    z2 = true;
                }
            }
        } while (z2);
    }

    @Override // kotlinx.coroutines.AbstractC5040y
    public final void r(CoroutineContext coroutineContext, Runnable runnable) {
        synchronized (this.d) {
            try {
                this.e.addLast(runnable);
                if (!this.h) {
                    this.h = true;
                    this.c.post(this.j);
                    if (!this.i) {
                        this.i = true;
                        this.b.postFrameCallback(this.j);
                    }
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
