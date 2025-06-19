package androidx.compose.material3.pulltorefresh;

import androidx.compose.animation.d0;
import androidx.compose.ui.node.T;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes.dex */
public final class PullToRefreshElement extends T {
    public final boolean b;
    public final Function0 c;
    public final q d;
    public final float e;

    public PullToRefreshElement(boolean z, Function0 function0, q qVar, float f) {
        this.b = z;
        this.c = function0;
        this.d = qVar;
        this.e = f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PullToRefreshElement)) {
            return false;
        }
        PullToRefreshElement pullToRefreshElement = (PullToRefreshElement) obj;
        return this.b == pullToRefreshElement.b && Intrinsics.b(this.c, pullToRefreshElement.c) && Intrinsics.b(this.d, pullToRefreshElement.d) && androidx.compose.ui.unit.e.a(this.e, pullToRefreshElement.e);
    }

    public final int hashCode() {
        return Float.hashCode(this.e) + ((this.d.hashCode() + d0.g((this.c.hashCode() + (Boolean.hashCode(this.b) * 31)) * 31, 31, true)) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new o(this.b, this.c, this.d, this.e);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        o oVar = (o) pVar;
        oVar.q = this.c;
        oVar.r = true;
        oVar.s = this.d;
        oVar.t = this.e;
        boolean z = oVar.p;
        boolean z2 = this.b;
        if (z != z2) {
            oVar.p = z2;
            E.A(oVar.A0(), null, null, new n(oVar, null), 3);
        }
    }

    public final String toString() {
        return "PullToRefreshElement(isRefreshing=" + this.b + ", onRefresh=" + this.c + ", enabled=true, state=" + this.d + ", threshold=" + ((Object) androidx.compose.ui.unit.e.b(this.e)) + ')';
    }
}
