package coil3.compose;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g implements h {
    public final androidx.compose.ui.graphics.painter.b a;
    public final coil3.request.o b;

    public g(androidx.compose.ui.graphics.painter.b bVar, coil3.request.o oVar) {
        this.a = bVar;
        this.b = oVar;
    }

    @Override // coil3.compose.h
    public final androidx.compose.ui.graphics.painter.b a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Success(painter=" + this.a + ", result=" + this.b + ')';
    }
}
