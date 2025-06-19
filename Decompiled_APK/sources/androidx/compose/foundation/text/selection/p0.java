package androidx.compose.foundation.text.selection;

import androidx.compose.ui.graphics.C0861v;

/* loaded from: classes.dex */
public final class p0 {
    public final long a;
    public final long b;

    public p0(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof p0)) {
            return false;
        }
        p0 p0Var = (p0) obj;
        return C0861v.c(this.a, p0Var.a) && C0861v.c(this.b, p0Var.b);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SelectionColors(selectionHandleColor=");
        androidx.compose.animation.d0.x(this.a, ", selectionBackgroundColor=", sb);
        sb.append((Object) C0861v.i(this.b));
        sb.append(')');
        return sb.toString();
    }
}
