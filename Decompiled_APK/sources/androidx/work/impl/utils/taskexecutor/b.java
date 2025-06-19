package androidx.work.impl.utils.taskexecutor;

import com.google.android.gms.measurement.internal.D0;
import com.google.android.gms.measurement.internal.X;
import com.google.android.gms.measurement.internal.Y;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class b implements Executor {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.util.concurrent.Executor
    public final void execute(Runnable runnable) {
        switch (this.a) {
            case 0:
                ((c) this.b).c.post(runnable);
                break;
            default:
                X x = ((Y) ((D0) this.b).b).j;
                Y.k(x);
                x.c0(runnable);
                break;
        }
    }
}
