package androidx.compose.animation;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class SizeAnimationModifierElement extends androidx.compose.ui.node.T {
    public final androidx.compose.animation.core.D b;

    public SizeAnimationModifierElement(androidx.compose.animation.core.D d) {
        this.b = d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SizeAnimationModifierElement)) {
            return false;
        }
        if (!Intrinsics.b(this.b, ((SizeAnimationModifierElement) obj).b)) {
            return false;
        }
        androidx.compose.ui.i iVar = androidx.compose.ui.b.a;
        return iVar.equals(iVar);
    }

    public final int hashCode() {
        return (Float.hashCode(-1.0f) + (Float.hashCode(-1.0f) * 31) + (this.b.hashCode() * 31)) * 31;
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        return new m0(this.b);
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        ((m0) pVar).o = this.b;
    }

    public final String toString() {
        return "SizeAnimationModifierElement(animationSpec=" + this.b + ", alignment=" + androidx.compose.ui.b.a + ", finishedListener=null)";
    }
}
