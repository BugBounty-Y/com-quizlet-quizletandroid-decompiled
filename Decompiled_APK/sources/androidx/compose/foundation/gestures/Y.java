package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Y extends Q {
    public S A;
    public kotlin.jvm.functions.c B;
    public boolean C;
    public Z x;
    public EnumC0320d0 y;
    public boolean z;

    @Override // androidx.compose.foundation.gestures.Q
    public final Object T0(O o, P p) {
        Object objA = this.x.a(new V(o, this, null), p);
        return objA == kotlin.coroutines.intrinsics.a.a ? objA : Unit.a;
    }

    @Override // androidx.compose.foundation.gestures.Q
    public final void U0(long j) {
        if (!this.m || Intrinsics.b(this.A, U.a)) {
            return;
        }
        kotlinx.coroutines.E.A(A0(), null, null, new W(this, j, null), 3);
    }

    @Override // androidx.compose.foundation.gestures.Q
    public final void V0(long j) {
        if (!this.m || Intrinsics.b(this.B, U.b)) {
            return;
        }
        kotlinx.coroutines.E.A(A0(), null, null, new X(this, j, null), 3);
    }

    @Override // androidx.compose.foundation.gestures.Q
    public final boolean W0() {
        return this.z;
    }
}
