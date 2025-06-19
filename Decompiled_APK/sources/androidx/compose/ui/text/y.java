package androidx.compose.ui.text;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class y {
    public final x a;
    public final w b;

    public y(x xVar, w wVar) {
        this.a = xVar;
        this.b = wVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof y)) {
            return false;
        }
        y yVar = (y) obj;
        return Intrinsics.b(this.b, yVar.b) && Intrinsics.b(this.a, yVar.a);
    }

    public final int hashCode() {
        x xVar = this.a;
        int iHashCode = (xVar != null ? xVar.hashCode() : 0) * 31;
        w wVar = this.b;
        return iHashCode + (wVar != null ? wVar.hashCode() : 0);
    }

    public final String toString() {
        return "PlatformTextStyle(spanStyle=" + this.a + ", paragraphSyle=" + this.b + ')';
    }
}
