package androidx.glance.appwidget;

/* loaded from: classes.dex */
public final class A implements androidx.glance.o {
    public final androidx.glance.unit.c a;

    public A(androidx.glance.unit.c cVar) {
        this.a = cVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof A) && this.a.equals(((A) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "CornerRadiusModifier(radius=" + this.a + ')';
    }
}
