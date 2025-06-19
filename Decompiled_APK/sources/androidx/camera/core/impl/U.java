package androidx.camera.core.impl;

import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final class U implements androidx.lifecycle.Z {
    public final AtomicBoolean a = new AtomicBoolean(true);
    public final androidx.camera.camera2.internal.p0 b;
    public final Executor c;

    public U(Executor executor, androidx.camera.camera2.internal.p0 p0Var) {
        this.c = executor;
        this.b = p0Var;
    }

    @Override // androidx.lifecycle.Z
    public final void a(Object obj) {
        this.c.execute(new androidx.activity.r(15, this, (V) obj));
    }
}
