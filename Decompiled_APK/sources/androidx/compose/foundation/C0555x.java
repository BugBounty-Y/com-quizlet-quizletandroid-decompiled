package androidx.compose.foundation;

/* renamed from: androidx.compose.foundation.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0555x {
    public final float a;
    public final androidx.compose.ui.graphics.X b;

    public C0555x(float f, androidx.compose.ui.graphics.X x) {
        this.a = f;
        this.b = x;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0555x)) {
            return false;
        }
        C0555x c0555x = (C0555x) obj;
        return androidx.compose.ui.unit.e.a(this.a, c0555x.a) && this.b.equals(c0555x.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "BorderStroke(width=" + ((Object) androidx.compose.ui.unit.e.b(this.a)) + ", brush=" + this.b + ')';
    }
}
