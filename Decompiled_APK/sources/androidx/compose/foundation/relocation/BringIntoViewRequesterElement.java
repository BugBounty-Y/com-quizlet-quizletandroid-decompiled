package androidx.compose.foundation.relocation;

import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class BringIntoViewRequesterElement extends T {
    public final c b;

    public BringIntoViewRequesterElement(c cVar) {
        this.b = cVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof BringIntoViewRequesterElement) {
            return Intrinsics.b(this.b, ((BringIntoViewRequesterElement) obj).b);
        }
        return false;
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        e eVar = new e();
        eVar.n = this.b;
        return eVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        e eVar = (e) pVar;
        c cVar = eVar.n;
        if (cVar != null) {
            cVar.a.n(eVar);
        }
        c cVar2 = this.b;
        if (cVar2 != null) {
            cVar2.a.b(eVar);
        }
        eVar.n = cVar2;
    }
}
