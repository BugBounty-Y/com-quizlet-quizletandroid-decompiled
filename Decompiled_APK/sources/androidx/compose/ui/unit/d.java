package androidx.compose.ui.unit;

import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d implements b {
    public final float a;
    public final float b;
    public final androidx.compose.ui.unit.fontscaling.a c;

    public d(float f, float f2, androidx.compose.ui.unit.fontscaling.a aVar) {
        this.a = f;
        this.b = f2;
        this.c = aVar;
    }

    @Override // androidx.compose.ui.unit.b
    public final float Z() {
        return this.b;
    }

    @Override // androidx.compose.ui.unit.b
    public final float a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return Float.compare(this.a, dVar.a) == 0 && Float.compare(this.b, dVar.b) == 0 && Intrinsics.b(this.c, dVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31);
    }

    @Override // androidx.compose.ui.unit.b
    public final long r(float f) {
        return S5.i(4294967296L, this.c.a(f));
    }

    public final String toString() {
        return "DensityWithConverter(density=" + this.a + ", fontScale=" + this.b + ", converter=" + this.c + ')';
    }

    @Override // androidx.compose.ui.unit.b
    public final float y(long j) {
        if (n.a(m.b(j), 4294967296L)) {
            return this.c.b(m.c(j));
        }
        throw new IllegalStateException("Only Sp can convert to Px");
    }
}
