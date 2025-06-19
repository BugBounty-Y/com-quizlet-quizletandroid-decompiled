package kotlinx.coroutines.flow.internal;

import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.q0;

/* loaded from: classes3.dex */
public final class H extends d0 implements q0 {
    @Override // kotlinx.coroutines.flow.q0
    public final Object getValue() {
        Integer numValueOf;
        synchronized (this) {
            Object[] objArr = this.h;
            Intrinsics.d(objArr);
            numValueOf = Integer.valueOf(((Number) objArr[((int) ((this.i + ((int) ((q() + this.k) - this.i))) - 1)) & (objArr.length - 1)]).intValue());
        }
        return numValueOf;
    }

    public final void x(int i) {
        synchronized (this) {
            Object[] objArr = this.h;
            Intrinsics.d(objArr);
            h(Integer.valueOf(((Number) objArr[((int) ((this.i + ((int) ((q() + this.k) - this.i))) - 1)) & (objArr.length - 1)]).intValue() + i));
        }
    }
}
