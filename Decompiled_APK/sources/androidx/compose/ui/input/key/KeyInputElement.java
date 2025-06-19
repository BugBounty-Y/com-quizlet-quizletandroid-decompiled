package androidx.compose.ui.input.key;

import androidx.compose.ui.node.T;
import androidx.compose.ui.p;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class KeyInputElement extends T {
    public final Function1 b;
    public final Function1 c;

    public KeyInputElement(Function1 function1, Function1 function12) {
        this.b = function1;
        this.c = function12;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof KeyInputElement)) {
            return false;
        }
        KeyInputElement keyInputElement = (KeyInputElement) obj;
        return Intrinsics.b(this.b, keyInputElement.b) && Intrinsics.b(this.c, keyInputElement.c);
    }

    public final int hashCode() {
        Function1 function1 = this.b;
        int iHashCode = (function1 == null ? 0 : function1.hashCode()) * 31;
        Function1 function12 = this.c;
        return iHashCode + (function12 != null ? function12.hashCode() : 0);
    }

    @Override // androidx.compose.ui.node.T
    public final p l() {
        e eVar = new e();
        eVar.n = this.b;
        eVar.o = this.c;
        return eVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(p pVar) {
        e eVar = (e) pVar;
        eVar.n = this.b;
        eVar.o = this.c;
    }

    public final String toString() {
        return "KeyInputElement(onKeyEvent=" + this.b + ", onPreKeyEvent=" + this.c + ')';
    }
}
