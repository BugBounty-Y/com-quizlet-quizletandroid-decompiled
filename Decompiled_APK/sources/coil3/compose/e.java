package coil3.compose;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e implements h {
    public final androidx.compose.ui.graphics.painter.b a;
    public final coil3.request.c b;

    public e(androidx.compose.ui.graphics.painter.b bVar, coil3.request.c cVar) {
        this.a = bVar;
        this.b = cVar;
    }

    @Override // coil3.compose.h
    public final androidx.compose.ui.graphics.painter.b a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b);
    }

    public final int hashCode() {
        androidx.compose.ui.graphics.painter.b bVar = this.a;
        return this.b.hashCode() + ((bVar == null ? 0 : bVar.hashCode()) * 31);
    }

    public final String toString() {
        return "Error(painter=" + this.a + ", result=" + this.b + ')';
    }
}
