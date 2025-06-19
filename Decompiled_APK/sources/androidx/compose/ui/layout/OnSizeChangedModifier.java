package androidx.compose.ui.layout;

import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;

@Metadata
/* loaded from: classes.dex */
final class OnSizeChangedModifier extends androidx.compose.ui.node.T {
    public final Function1 b;

    public OnSizeChangedModifier(Function1 function1) {
        this.b = function1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof OnSizeChangedModifier) {
            return this.b == ((OnSizeChangedModifier) obj).b;
        }
        return false;
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        S s = new S();
        s.n = this.b;
        s.o = R5.a(Integer.MIN_VALUE, Integer.MIN_VALUE);
        return s;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        S s = (S) pVar;
        s.n = this.b;
        s.o = R5.a(Integer.MIN_VALUE, Integer.MIN_VALUE);
    }
}
