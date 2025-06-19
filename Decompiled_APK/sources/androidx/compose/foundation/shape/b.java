package androidx.compose.foundation.shape;

/* loaded from: classes.dex */
public final class b implements a {
    public final float a;

    public b(float f) {
        this.a = f;
    }

    @Override // androidx.compose.foundation.shape.a
    public final float a(long j, androidx.compose.ui.unit.b bVar) {
        return bVar.c0(this.a);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && androidx.compose.ui.unit.e.a(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return Float.hashCode(this.a);
    }

    public final String toString() {
        return "CornerSize(size = " + this.a + ".dp)";
    }
}
