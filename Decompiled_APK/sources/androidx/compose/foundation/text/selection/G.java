package androidx.compose.foundation.text.selection;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes.dex */
public final class G {
    public final androidx.compose.foundation.text.U a;
    public final long b;
    public final int c;
    public final boolean d;

    public G(androidx.compose.foundation.text.U u, long j, int i, boolean z) {
        this.a = u;
        this.b = j;
        this.c = i;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof G)) {
            return false;
        }
        G g = (G) obj;
        return this.a == g.a && androidx.compose.ui.geometry.b.b(this.b, g.b) && this.c == g.c && this.d == g.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + ((AbstractC0147y.k(this.c) + androidx.compose.animation.d0.d(this.a.hashCode() * 31, 31, this.b)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SelectionHandleInfo(handle=");
        sb.append(this.a);
        sb.append(", position=");
        sb.append((Object) androidx.compose.ui.geometry.b.j(this.b));
        sb.append(", anchor=");
        int i = this.c;
        sb.append(i != 1 ? i != 2 ? i != 3 ? "null" : "Right" : "Middle" : "Left");
        sb.append(", visible=");
        return android.support.v4.media.session.a.u(sb, this.d, ')');
    }
}
