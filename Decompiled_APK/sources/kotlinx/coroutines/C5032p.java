package kotlinx.coroutines;

/* renamed from: kotlinx.coroutines.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5032p extends l0 implements InterfaceC5031o {
    public final q0 e;

    public C5032p(q0 q0Var) {
        this.e = q0Var;
    }

    @Override // kotlinx.coroutines.InterfaceC5031o
    public final boolean c(Throwable th) {
        return i().E(th);
    }

    @Override // kotlinx.coroutines.l0
    public final boolean j() {
        return true;
    }

    @Override // kotlinx.coroutines.l0
    public final void k(Throwable th) {
        this.e.x(i());
    }
}
