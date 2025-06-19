package androidx.constraintlayout.compose;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class d {
    public final Object a;
    public final int b;
    public final b c;

    public d(Object obj, int i, b bVar) {
        this.a = obj;
        this.b = i;
        this.c = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a.equals(dVar.a) && this.b == dVar.b && this.c.equals(dVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        return "VerticalAnchor(id=" + this.a + ", index=" + this.b + ", reference=" + this.c + ')';
    }
}
