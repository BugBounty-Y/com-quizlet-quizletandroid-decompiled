package androidx.camera.core.impl;

import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes.dex */
public final class n0 implements o0 {
    public final AtomicBoolean a = new AtomicBoolean(false);
    public final o0 b;

    public n0(o0 o0Var) {
        this.b = o0Var;
    }

    @Override // androidx.camera.core.impl.o0
    public final void a(q0 q0Var) {
        if (this.a.get()) {
            return;
        }
        this.b.a(q0Var);
    }

    public final void b() {
        this.a.set(true);
    }
}
