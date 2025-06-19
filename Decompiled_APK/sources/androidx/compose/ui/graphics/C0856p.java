package androidx.compose.ui.graphics;

/* renamed from: androidx.compose.ui.graphics.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0856p extends P {
    public final float b;
    public final float c;
    public final int d;

    public C0856p(float f, float f2, int i) {
        this.b = f;
        this.c = f2;
        this.d = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0856p)) {
            return false;
        }
        C0856p c0856p = (C0856p) obj;
        return this.b == c0856p.b && this.c == c0856p.c && this.d == c0856p.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + android.support.v4.media.session.a.b(Float.hashCode(this.b) * 31, this.c, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BlurEffect(renderEffect=null, radiusX=");
        sb.append(this.b);
        sb.append(", radiusY=");
        sb.append(this.c);
        sb.append(", edgeTreatment=");
        int i = this.d;
        sb.append((Object) (i == 0 ? "Clamp" : i == 1 ? "Repeated" : i == 2 ? "Mirror" : i == 3 ? "Decal" : "Unknown"));
        sb.append(')');
        return sb.toString();
    }
}
