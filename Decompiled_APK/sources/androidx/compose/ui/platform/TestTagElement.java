package androidx.compose.ui.platform;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class TestTagElement extends androidx.compose.ui.node.T {
    public final String b;

    public TestTagElement(String str) {
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TestTagElement)) {
            return false;
        }
        return Intrinsics.b(this.b, ((TestTagElement) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        R0 r0 = new R0();
        r0.n = this.b;
        return r0;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((R0) pVar).n = this.b;
    }
}
