package androidx.compose.ui.text;

import androidx.compose.animation.d0;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G {
    public final C0995g a;
    public final L b;
    public final List c;
    public final int d;
    public final boolean e;
    public final int f;
    public final androidx.compose.ui.unit.b g;
    public final androidx.compose.ui.unit.k h;
    public final androidx.compose.ui.text.font.i i;
    public final long j;

    public G(C0995g c0995g, L l, List list, int i, boolean z, int i2, androidx.compose.ui.unit.b bVar, androidx.compose.ui.unit.k kVar, androidx.compose.ui.text.font.i iVar, long j) {
        this.a = c0995g;
        this.b = l;
        this.c = list;
        this.d = i;
        this.e = z;
        this.f = i2;
        this.g = bVar;
        this.h = kVar;
        this.i = iVar;
        this.j = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof G)) {
            return false;
        }
        G g = (G) obj;
        return Intrinsics.b(this.a, g.a) && Intrinsics.b(this.b, g.b) && Intrinsics.b(this.c, g.c) && this.d == g.d && this.e == g.e && this.f == g.f && Intrinsics.b(this.g, g.g) && this.h == g.h && Intrinsics.b(this.i, g.i) && androidx.compose.ui.unit.a.b(this.j, g.j);
    }

    public final int hashCode() {
        return Long.hashCode(this.j) + ((this.i.hashCode() + ((this.h.hashCode() + ((this.g.hashCode() + d0.b(this.f, d0.g((d0.f((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c) + this.d) * 31, 31, this.e), 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TextLayoutInput(text=");
        sb.append((Object) this.a);
        sb.append(", style=");
        sb.append(this.b);
        sb.append(", placeholders=");
        sb.append(this.c);
        sb.append(", maxLines=");
        sb.append(this.d);
        sb.append(", softWrap=");
        sb.append(this.e);
        sb.append(", overflow=");
        int i = this.f;
        sb.append((Object) (i == 1 ? "Clip" : i == 2 ? "Ellipsis" : i == 3 ? "Visible" : "Invalid"));
        sb.append(", density=");
        sb.append(this.g);
        sb.append(", layoutDirection=");
        sb.append(this.h);
        sb.append(", fontFamilyResolver=");
        sb.append(this.i);
        sb.append(", constraints=");
        sb.append((Object) androidx.compose.ui.unit.a.l(this.j));
        sb.append(')');
        return sb.toString();
    }
}
