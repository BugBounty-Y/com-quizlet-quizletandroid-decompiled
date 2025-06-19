package androidx.compose.foundation.text.selection;

/* renamed from: androidx.compose.foundation.text.selection.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0535p {
    public final androidx.compose.ui.text.style.h a;
    public final int b;
    public final long c;

    public C0535p(androidx.compose.ui.text.style.h hVar, int i, long j) {
        this.a = hVar;
        this.b = i;
        this.c = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0535p)) {
            return false;
        }
        C0535p c0535p = (C0535p) obj;
        return this.a == c0535p.a && this.b == c0535p.b && this.c == c0535p.c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AnchorInfo(direction=");
        sb.append(this.a);
        sb.append(", offset=");
        sb.append(this.b);
        sb.append(", selectableId=");
        return androidx.compose.animation.d0.q(sb, this.c, ')');
    }
}
