package androidx.compose.ui.geometry;

import com.google.android.gms.internal.mlkit_vision_barcode.P4;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes.dex */
public final class c {
    public static final c e = new c(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
    public final float a;
    public final float b;
    public final float c;
    public final float d;

    public c(float f, float f2, float f3, float f4) {
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
    }

    public static c b(c cVar, float f, float f2, float f3, int i) {
        if ((i & 1) != 0) {
            f = cVar.a;
        }
        if ((i & 4) != 0) {
            f2 = cVar.c;
        }
        if ((i & 8) != 0) {
            f3 = cVar.d;
        }
        return new c(f, cVar.b, f2, f3);
    }

    public final boolean a(long j) {
        return b.d(j) >= this.a && b.d(j) < this.c && b.e(j) >= this.b && b.e(j) < this.d;
    }

    public final long c() {
        return Q4.c((e() / 2.0f) + this.a, (d() / 2.0f) + this.b);
    }

    public final float d() {
        return this.d - this.b;
    }

    public final float e() {
        return this.c - this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Float.compare(this.a, cVar.a) == 0 && Float.compare(this.b, cVar.b) == 0 && Float.compare(this.c, cVar.c) == 0 && Float.compare(this.d, cVar.d) == 0;
    }

    public final c f(c cVar) {
        return new c(Math.max(this.a, cVar.a), Math.max(this.b, cVar.b), Math.min(this.c, cVar.c), Math.min(this.d, cVar.d));
    }

    public final boolean g() {
        return this.a >= this.c || this.b >= this.d;
    }

    public final boolean h(c cVar) {
        return this.c > cVar.a && cVar.c > this.a && this.d > cVar.b && cVar.d > this.b;
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31), this.c, 31);
    }

    public final c i(float f, float f2) {
        return new c(this.a + f, this.b + f2, this.c + f, this.d + f2);
    }

    public final c j(long j) {
        return new c(b.d(j) + this.a, b.e(j) + this.b, b.d(j) + this.c, b.e(j) + this.d);
    }

    public final String toString() {
        return "Rect.fromLTRB(" + P4.e(this.a) + ", " + P4.e(this.b) + ", " + P4.e(this.c) + ", " + P4.e(this.d) + ')';
    }
}
