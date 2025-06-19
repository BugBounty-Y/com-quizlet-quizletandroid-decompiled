package androidx.constraintlayout.compose;

import androidx.compose.ui.layout.T;
import androidx.compose.ui.platform.N;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class f extends N implements T {
    public final b d;
    public final Function1 e;

    public f(b bVar, Function1 function1) {
        this.d = bVar;
        this.e = function1;
    }

    public final boolean equals(Object obj) {
        f fVar = obj instanceof f ? (f) obj : null;
        return this.e == (fVar != null ? fVar.e : null);
    }

    public final int hashCode() {
        return this.e.hashCode();
    }

    @Override // androidx.compose.ui.layout.T
    public final Object k() {
        return new e(this.d, this.e);
    }
}
