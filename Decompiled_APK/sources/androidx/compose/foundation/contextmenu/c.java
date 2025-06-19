package androidx.compose.foundation.contextmenu;

import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.C0861v;
import kotlin.C;
import kotlin.D;

/* loaded from: classes.dex */
public final class c {
    public final long a;
    public final long b;
    public final long c;
    public final long d;
    public final long e;

    public c(long j, long j2, long j3, long j4, long j5) {
        this.a = j;
        this.b = j2;
        this.c = j3;
        this.d = j4;
        this.e = j5;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return C0861v.c(this.a, cVar.a) && C0861v.c(this.b, cVar.b) && C0861v.c(this.c, cVar.c) && C0861v.c(this.d, cVar.d) && C0861v.c(this.e, cVar.e);
    }

    public final int hashCode() {
        int i = C0861v.h;
        C c = D.b;
        return Long.hashCode(this.e) + d0.d(d0.d(d0.d(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ContextMenuColors(backgroundColor=");
        d0.x(this.a, ", textColor=", sb);
        d0.x(this.b, ", iconColor=", sb);
        d0.x(this.c, ", disabledTextColor=", sb);
        d0.x(this.d, ", disabledIconColor=", sb);
        sb.append((Object) C0861v.i(this.e));
        sb.append(')');
        return sb.toString();
    }
}
