package androidx.compose.material3;

/* renamed from: androidx.compose.material3.r4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0714r4 {
    public final float a;
    public final float b;
    public final float c;

    public C0714r4(float f, float f2, float f3) {
        this.a = f;
        this.b = f2;
        this.c = f3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0714r4)) {
            return false;
        }
        C0714r4 c0714r4 = (C0714r4) obj;
        return androidx.compose.ui.unit.e.a(this.a, c0714r4.a) && androidx.compose.ui.unit.e.a(this.b, c0714r4.b) && androidx.compose.ui.unit.e.a(this.c, c0714r4.c);
    }

    public final int hashCode() {
        return Float.hashCode(this.c) + android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TabPosition(left=");
        float f = this.a;
        sb.append((Object) androidx.compose.ui.unit.e.b(f));
        sb.append(", right=");
        float f2 = this.b;
        sb.append((Object) androidx.compose.ui.unit.e.b(f + f2));
        sb.append(", width=");
        sb.append((Object) androidx.compose.ui.unit.e.b(f2));
        sb.append(", contentWidth=");
        sb.append((Object) androidx.compose.ui.unit.e.b(this.c));
        sb.append(')');
        return sb.toString();
    }
}
