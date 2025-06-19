package androidx.compose.foundation;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class BorderModifierNodeElement extends androidx.compose.ui.node.T {
    public final float b;
    public final androidx.compose.ui.graphics.X c;
    public final androidx.compose.ui.graphics.V d;

    public BorderModifierNodeElement(float f, androidx.compose.ui.graphics.X x, androidx.compose.ui.graphics.V v) {
        this.b = f;
        this.c = x;
        this.d = v;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BorderModifierNodeElement)) {
            return false;
        }
        BorderModifierNodeElement borderModifierNodeElement = (BorderModifierNodeElement) obj;
        return androidx.compose.ui.unit.e.a(this.b, borderModifierNodeElement.b) && this.c.equals(borderModifierNodeElement.c) && Intrinsics.b(this.d, borderModifierNodeElement.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + (Float.hashCode(this.b) * 31)) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new C0554w(this.b, this.c, this.d);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0554w c0554w = (C0554w) pVar;
        float f = c0554w.q;
        float f2 = this.b;
        boolean zA = androidx.compose.ui.unit.e.a(f, f2);
        androidx.compose.ui.draw.c cVar = c0554w.t;
        if (!zA) {
            c0554w.q = f2;
            cVar.M0();
        }
        androidx.compose.ui.graphics.X x = c0554w.r;
        androidx.compose.ui.graphics.X x2 = this.c;
        if (!Intrinsics.b(x, x2)) {
            c0554w.r = x2;
            cVar.M0();
        }
        androidx.compose.ui.graphics.V v = c0554w.s;
        androidx.compose.ui.graphics.V v2 = this.d;
        if (Intrinsics.b(v, v2)) {
            return;
        }
        c0554w.s = v2;
        cVar.M0();
    }

    public final String toString() {
        return "BorderModifierNodeElement(width=" + ((Object) androidx.compose.ui.unit.e.b(this.b)) + ", brush=" + this.c + ", shape=" + this.d + ')';
    }
}
