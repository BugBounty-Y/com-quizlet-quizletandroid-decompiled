package assistantMode.types;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h {
    public final long a;
    public final String b;
    public final long c;

    public h(long j, long j2, String shape) {
        Intrinsics.checkNotNullParameter(shape, "shape");
        this.a = j;
        this.b = shape;
        this.c = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a == hVar.a && Intrinsics.b(this.b, hVar.b) && this.c == hVar.c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + d0.e(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DiagramShape(setId=");
        sb.append(this.a);
        sb.append(", shape=");
        sb.append(this.b);
        sb.append(", termId=");
        return android.support.v4.media.session.a.g(this.c, ")", sb);
    }
}
