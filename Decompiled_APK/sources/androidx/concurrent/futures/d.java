package androidx.concurrent.futures;

import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public final class d {
    public static final d d = new d(null, null);
    public final Runnable a;
    public final Executor b;
    public d c;

    public d(Runnable runnable, Executor executor) {
        this.a = runnable;
        this.b = executor;
    }
}
