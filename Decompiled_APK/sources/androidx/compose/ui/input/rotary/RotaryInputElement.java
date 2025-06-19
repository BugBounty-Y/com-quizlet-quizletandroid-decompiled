package androidx.compose.ui.input.rotary;

import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import androidx.compose.ui.platform.C0956n;
import kotlin.Metadata;

@Metadata
/* loaded from: classes.dex */
final class RotaryInputElement extends T {
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RotaryInputElement)) {
            return false;
        }
        ((RotaryInputElement) obj).getClass();
        Object obj2 = C0956n.d;
        return obj2.equals(obj2);
    }

    public final int hashCode() {
        return C0956n.d.hashCode() * 31;
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        b bVar = new b();
        bVar.n = C0956n.d;
        return bVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        ((b) pVar).n = C0956n.d;
    }

    public final String toString() {
        return "RotaryInputElement(onRotaryScrollEvent=" + C0956n.d + ", onPreRotaryScrollEvent=null)";
    }
}
