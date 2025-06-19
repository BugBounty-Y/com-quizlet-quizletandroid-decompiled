package androidx.compose.foundation.layout;

import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.Metadata;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class WrapContentElement extends androidx.compose.ui.node.T {
    public final int b;
    public final kotlin.jvm.internal.r c;
    public final Object d;

    /* JADX WARN: Multi-variable type inference failed */
    public WrapContentElement(int i, Function2 function2, Object obj) {
        this.b = i;
        this.c = (kotlin.jvm.internal.r) function2;
        this.d = obj;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || WrapContentElement.class != obj.getClass()) {
            return false;
        }
        WrapContentElement wrapContentElement = (WrapContentElement) obj;
        return this.b == wrapContentElement.b && Intrinsics.b(this.d, wrapContentElement.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + androidx.compose.animation.d0.g(AbstractC0147y.k(this.b) * 31, 31, false);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        V0 v0 = new V0();
        v0.n = this.b;
        v0.o = this.c;
        return v0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        V0 v0 = (V0) pVar;
        v0.n = this.b;
        v0.o = this.c;
    }
}
