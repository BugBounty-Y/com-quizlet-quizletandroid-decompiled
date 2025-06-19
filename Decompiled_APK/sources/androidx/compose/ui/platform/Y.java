package androidx.compose.ui.platform;

import android.view.Choreographer;
import java.util.ArrayList;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class Y implements Choreographer.FrameCallback, Runnable {
    public final /* synthetic */ Z a;

    public Y(Z z) {
        this.a = z;
    }

    @Override // android.view.Choreographer.FrameCallback
    public final void doFrame(long j) {
        this.a.c.removeCallbacks(this);
        Z.k0(this.a);
        Z z = this.a;
        synchronized (z.d) {
            if (z.i) {
                z.i = false;
                ArrayList arrayList = z.f;
                z.f = z.g;
                z.g = arrayList;
                int size = arrayList.size();
                for (int i = 0; i < size; i++) {
                    ((Choreographer.FrameCallback) arrayList.get(i)).doFrame(j);
                }
                arrayList.clear();
            }
        }
    }

    @Override // java.lang.Runnable
    public final void run() {
        Z.k0(this.a);
        Z z = this.a;
        synchronized (z.d) {
            try {
                if (z.f.isEmpty()) {
                    z.b.removeFrameCallback(this);
                    z.i = false;
                }
                Unit unit = Unit.a;
            } catch (Throwable th) {
                throw th;
            }
        }
    }
}
