package androidx.glance.appwidget;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class G {
    public final androidx.glance.p a;
    public final androidx.glance.p b;

    public G(androidx.glance.p pVar, androidx.glance.p pVar2) {
        this.a = pVar;
        this.b = pVar2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof G)) {
            return false;
        }
        G g = (G) obj;
        return Intrinsics.b(this.a, g.a) && Intrinsics.b(this.b, g.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ExtractedSizeModifiers(sizeModifiers=" + this.a + ", nonSizeModifiers=" + this.b + ')';
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public /* synthetic */ G(androidx.glance.p pVar, int i) {
        androidx.glance.n nVar = androidx.glance.n.a;
        this(nVar, (i & 2) != 0 ? nVar : pVar);
    }
}
