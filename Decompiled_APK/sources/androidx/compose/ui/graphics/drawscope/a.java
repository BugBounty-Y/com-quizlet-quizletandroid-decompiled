package androidx.compose.ui.graphics.drawscope;

import androidx.compose.ui.graphics.InterfaceC0858s;
import androidx.compose.ui.unit.k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public androidx.compose.ui.unit.b a;
    public k b;
    public InterfaceC0858s c;
    public long d;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b && Intrinsics.b(this.c, aVar.c) && androidx.compose.ui.geometry.e.a(this.d, aVar.d);
    }

    public final int hashCode() {
        return Long.hashCode(this.d) + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "DrawParams(density=" + this.a + ", layoutDirection=" + this.b + ", canvas=" + this.c + ", size=" + ((Object) androidx.compose.ui.geometry.e.f(this.d)) + ')';
    }
}
