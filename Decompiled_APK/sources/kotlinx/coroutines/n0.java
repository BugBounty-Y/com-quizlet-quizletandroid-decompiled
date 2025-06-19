package kotlinx.coroutines;

/* loaded from: classes3.dex */
public final class n0 extends l0 {
    public final q0 e;
    public final o0 f;
    public final C5032p g;
    public final Object h;

    public n0(q0 q0Var, o0 o0Var, C5032p c5032p, Object obj) {
        this.e = q0Var;
        this.f = o0Var;
        this.g = c5032p;
        this.h = obj;
    }

    @Override // kotlinx.coroutines.l0
    public final boolean j() {
        return false;
    }

    @Override // kotlinx.coroutines.l0
    public final void k(Throwable th) {
        C5032p c5032p = this.g;
        q0 q0Var = this.e;
        q0Var.getClass();
        C5032p c5032pX = q0.X(c5032p);
        o0 o0Var = this.f;
        Object obj = this.h;
        if (c5032pX == null || !q0Var.j0(o0Var, c5032pX, obj)) {
            o0Var.a.d(new kotlinx.coroutines.internal.h(2), 2);
            C5032p c5032pX2 = q0.X(c5032p);
            if (c5032pX2 == null || !q0Var.j0(o0Var, c5032pX2, obj)) {
                q0Var.u(q0Var.H(o0Var, obj));
            }
        }
    }
}
