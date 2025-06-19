package androidx.constraintlayout.compose;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class c {
    public final Object a;
    public final int b;
    public final b c;

    public c(Object obj, int i, b bVar) {
        this.a = obj;
        this.b = i;
        this.c = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a.equals(cVar.a) && this.b == cVar.b && this.c.equals(cVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        return "HorizontalAnchor(id=" + this.a + ", index=" + this.b + ", reference=" + this.c + ')';
    }
}
