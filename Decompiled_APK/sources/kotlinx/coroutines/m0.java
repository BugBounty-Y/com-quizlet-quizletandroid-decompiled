package kotlinx.coroutines;

/* loaded from: classes3.dex */
public final class m0 extends C5028l {
    public final q0 i;

    public m0(kotlin.coroutines.h hVar, q0 q0Var) {
        super(1, hVar);
        this.i = q0Var;
    }

    @Override // kotlinx.coroutines.C5028l
    public final String B() {
        return "AwaitContinuation";
    }

    @Override // kotlinx.coroutines.C5028l
    public final Throwable p(q0 q0Var) {
        Throwable thD;
        q0 q0Var2 = this.i;
        q0Var2.getClass();
        Object obj = q0.a.get(q0Var2);
        return (!(obj instanceof o0) || (thD = ((o0) obj).d()) == null) ? obj instanceof C5036u ? ((C5036u) obj).a : q0Var.y() : thD;
    }
}
