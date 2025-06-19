package kotlinx.coroutines.scheduling;

import androidx.compose.animation.d0;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class j extends i {
    public final Runnable c;

    public j(Runnable runnable, long j, boolean z) {
        super(j, z);
        this.c = runnable;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.c.run();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Task[");
        Runnable runnable = this.c;
        sb.append(runnable.getClass().getSimpleName());
        sb.append('@');
        sb.append(E.r(runnable));
        sb.append(", ");
        sb.append(this.a);
        sb.append(", ");
        return d0.r(sb, this.b ? "Blocking" : "Non-blocking", ']');
    }
}
