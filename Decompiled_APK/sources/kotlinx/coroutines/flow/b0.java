package kotlinx.coroutines.flow;

import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5028l;

/* loaded from: classes3.dex */
public final class b0 implements kotlinx.coroutines.Q {
    public final d0 a;
    public final long b;
    public final Object c;
    public final C5028l d;

    public b0(d0 d0Var, long j, Object obj, C5028l c5028l) {
        this.a = d0Var;
        this.b = j;
        this.c = obj;
        this.d = c5028l;
    }

    @Override // kotlinx.coroutines.Q
    public final void dispose() {
        d0 d0Var = this.a;
        synchronized (d0Var) {
            if (this.b < d0Var.q()) {
                return;
            }
            Object[] objArr = d0Var.h;
            Intrinsics.d(objArr);
            long j = this.b;
            if (objArr[((int) j) & (objArr.length - 1)] != this) {
                return;
            }
            e0.e(objArr, j, e0.a);
            d0Var.l();
            Unit unit = Unit.a;
        }
    }
}
