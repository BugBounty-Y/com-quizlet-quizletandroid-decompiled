package androidx.compose.ui.input.pointer;

import androidx.compose.foundation.text.u0;
import androidx.compose.ui.node.T;
import kotlin.Metadata;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class SuspendPointerInputElement extends T {
    public final Object b;
    public final Object c;
    public final Function2 d;

    public SuspendPointerInputElement(Object obj, u0 u0Var, Function2 function2, int i) {
        u0Var = (i & 2) != 0 ? null : u0Var;
        this.b = obj;
        this.c = u0Var;
        this.d = function2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SuspendPointerInputElement)) {
            return false;
        }
        SuspendPointerInputElement suspendPointerInputElement = (SuspendPointerInputElement) obj;
        return Intrinsics.b(this.b, suspendPointerInputElement.b) && Intrinsics.b(this.c, suspendPointerInputElement.c) && this.d == suspendPointerInputElement.d;
    }

    public final int hashCode() {
        Object obj = this.b;
        int iHashCode = (obj != null ? obj.hashCode() : 0) * 31;
        Object obj2 = this.c;
        return this.d.hashCode() + ((iHashCode + (obj2 != null ? obj2.hashCode() : 0)) * 961);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new B(this.b, this.c, this.d);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        B b = (B) pVar;
        Object obj = b.n;
        Object obj2 = this.b;
        boolean z = !Intrinsics.b(obj, obj2);
        b.n = obj2;
        Object obj3 = b.o;
        Object obj4 = this.c;
        boolean z2 = Intrinsics.b(obj3, obj4) ? z : true;
        b.o = obj4;
        if (z2) {
            b.O0();
        }
        b.p = this.d;
    }
}
