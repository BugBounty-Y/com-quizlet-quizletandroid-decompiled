package coil3.compose;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f implements h {
    public final androidx.compose.ui.graphics.painter.b a;

    public f(androidx.compose.ui.graphics.painter.b bVar) {
        this.a = bVar;
    }

    @Override // coil3.compose.h
    public final androidx.compose.ui.graphics.painter.b a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        androidx.compose.ui.graphics.painter.b bVar = this.a;
        if (bVar == null) {
            return 0;
        }
        return bVar.hashCode();
    }

    public final String toString() {
        return "Loading(painter=" + this.a + ')';
    }
}
