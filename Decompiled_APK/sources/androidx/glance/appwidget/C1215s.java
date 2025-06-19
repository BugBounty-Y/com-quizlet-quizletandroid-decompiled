package androidx.glance.appwidget;

/* renamed from: androidx.glance.appwidget.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1215s {
    public final u0 a;
    public final int b;
    public final int c;

    public C1215s(u0 u0Var, int i, int i2) {
        this.a = u0Var;
        this.b = i;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1215s)) {
            return false;
        }
        C1215s c1215s = (C1215s) obj;
        return this.a == c1215s.a && this.b == c1215s.b && this.c == c1215s.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        return "BoxChildSelector(type=" + this.a + ", horizontalAlignment=" + ((Object) androidx.glance.layout.a.b(this.b)) + ", verticalAlignment=" + ((Object) androidx.glance.layout.b.b(this.c)) + ')';
    }
}
