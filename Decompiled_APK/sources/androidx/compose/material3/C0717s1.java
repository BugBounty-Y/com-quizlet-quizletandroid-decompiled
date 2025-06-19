package androidx.compose.material3;

/* renamed from: androidx.compose.material3.s1, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0717s1 {
    public final float a;
    public final float b;
    public final float c;
    public final float d;

    public C0717s1(float f, float f2, float f3, float f4) {
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof C0717s1)) {
            return false;
        }
        C0717s1 c0717s1 = (C0717s1) obj;
        if (androidx.compose.ui.unit.e.a(this.a, c0717s1.a) && androidx.compose.ui.unit.e.a(this.b, c0717s1.b) && androidx.compose.ui.unit.e.a(this.c, c0717s1.c)) {
            return androidx.compose.ui.unit.e.a(this.d, c0717s1.d);
        }
        return false;
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31), this.c, 31);
    }
}
