package androidx.compose.ui.graphics;

import androidx.compose.animation.d0;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class U {
    public static final U d = new U();
    public final long a;
    public final long b;
    public final float c;

    public U(long j, long j2, float f) {
        this.a = j;
        this.b = j2;
        this.c = f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof U)) {
            return false;
        }
        U u = (U) obj;
        return C0861v.c(this.a, u.a) && androidx.compose.ui.geometry.b.b(this.b, u.b) && this.c == u.c;
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Float.hashCode(this.c) + d0.d(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Shadow(color=");
        d0.x(this.a, ", offset=", sb);
        sb.append((Object) androidx.compose.ui.geometry.b.j(this.b));
        sb.append(", blurRadius=");
        return android.support.v4.media.session.a.p(sb, this.c, ')');
    }

    public /* synthetic */ U() {
        this(F.d(4278190080L), 0L, DefinitionKt.NO_Float_VALUE);
    }
}
