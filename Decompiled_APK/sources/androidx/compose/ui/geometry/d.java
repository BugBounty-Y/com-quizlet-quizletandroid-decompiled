package androidx.compose.ui.geometry;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_barcode.O4;
import com.google.android.gms.internal.mlkit_vision_barcode.P4;

/* loaded from: classes.dex */
public final class d {
    public final float a;
    public final float b;
    public final float c;
    public final float d;
    public final long e;
    public final long f;
    public final long g;
    public final long h;

    static {
        long j = a.a;
        O4.a(a.b(j), a.c(j));
    }

    public d(float f, float f2, float f3, float f4, long j, long j2, long j3, long j4) {
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
        this.e = j;
        this.f = j2;
        this.g = j3;
        this.h = j4;
    }

    public final float a() {
        return this.d - this.b;
    }

    public final float b() {
        return this.c - this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Float.compare(this.a, dVar.a) == 0 && Float.compare(this.b, dVar.b) == 0 && Float.compare(this.c, dVar.c) == 0 && Float.compare(this.d, dVar.d) == 0 && a.a(this.e, dVar.e) && a.a(this.f, dVar.f) && a.a(this.g, dVar.g) && a.a(this.h, dVar.h);
    }

    public final int hashCode() {
        int iB = android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31), this.c, 31), this.d, 31);
        int i = a.b;
        return Long.hashCode(this.h) + d0.d(d0.d(d0.d(iB, 31, this.e), 31, this.f), 31, this.g);
    }

    public final String toString() {
        String str = P4.e(this.a) + ", " + P4.e(this.b) + ", " + P4.e(this.c) + ", " + P4.e(this.d);
        long j = this.e;
        long j2 = this.f;
        boolean zA = a.a(j, j2);
        long j3 = this.g;
        long j4 = this.h;
        if (!zA || !a.a(j2, j3) || !a.a(j3, j4)) {
            StringBuilder sbY = android.support.v4.media.session.a.y("RoundRect(rect=", str, ", topLeft=");
            sbY.append((Object) a.d(j));
            sbY.append(", topRight=");
            sbY.append((Object) a.d(j2));
            sbY.append(", bottomRight=");
            sbY.append((Object) a.d(j3));
            sbY.append(", bottomLeft=");
            sbY.append((Object) a.d(j4));
            sbY.append(')');
            return sbY.toString();
        }
        if (a.b(j) == a.c(j)) {
            StringBuilder sbY2 = android.support.v4.media.session.a.y("RoundRect(rect=", str, ", radius=");
            sbY2.append(P4.e(a.b(j)));
            sbY2.append(')');
            return sbY2.toString();
        }
        StringBuilder sbY3 = android.support.v4.media.session.a.y("RoundRect(rect=", str, ", x=");
        sbY3.append(P4.e(a.b(j)));
        sbY3.append(", y=");
        sbY3.append(P4.e(a.c(j)));
        sbY3.append(')');
        return sbY3.toString();
    }
}
