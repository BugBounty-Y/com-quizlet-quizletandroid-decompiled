package kotlinx.coroutines;

import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class S extends l0 {
    public final /* synthetic */ int e;
    public final Object f;

    public /* synthetic */ S(Object obj, int i) {
        this.e = i;
        this.f = obj;
    }

    @Override // kotlinx.coroutines.l0
    public final boolean j() {
        switch (this.e) {
        }
        return false;
    }

    @Override // kotlinx.coroutines.l0
    public final void k(Throwable th) {
        Object obj = this.f;
        switch (this.e) {
            case 0:
                ((Q) obj).dispose();
                break;
            case 1:
                ((Function1) obj).invoke(th);
                break;
            default:
                Object obj2 = q0.a.get(i());
                m0 m0Var = (m0) obj;
                if (!(obj2 instanceof C5036u)) {
                    kotlin.p pVar = kotlin.r.b;
                    m0Var.resumeWith(E.I(obj2));
                    break;
                } else {
                    kotlin.p pVar2 = kotlin.r.b;
                    m0Var.resumeWith(androidx.glance.appwidget.protobuf.Z.b(((C5036u) obj2).a));
                    break;
                }
        }
    }
}
