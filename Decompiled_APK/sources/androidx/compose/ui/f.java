package androidx.compose.ui;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;

/* loaded from: classes.dex */
public final class f implements d {
    public final float a;

    public f(float f) {
        this.a = f;
    }

    @Override // androidx.compose.ui.d
    public final long a(long j, long j2, androidx.compose.ui.unit.k kVar) {
        long jA = R5.a(((int) (j2 >> 32)) - ((int) (j >> 32)), ((int) (j2 & 4294967295L)) - ((int) (j & 4294967295L)));
        float f = 1;
        return P5.b(Math.round((this.a + f) * (((int) (jA >> 32)) / 2.0f)), Math.round((f - 1.0f) * (((int) (jA & 4294967295L)) / 2.0f)));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof f) {
            return Float.compare(this.a, ((f) obj).a) == 0 && Float.compare(-1.0f, -1.0f) == 0;
        }
        return false;
    }

    public final int hashCode() {
        return Float.hashCode(-1.0f) + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "BiasAbsoluteAlignment(horizontalBias=" + this.a + ", verticalBias=-1.0)";
    }
}
