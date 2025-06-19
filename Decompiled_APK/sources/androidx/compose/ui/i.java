package androidx.compose.ui;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;

/* loaded from: classes.dex */
public final class i implements d {
    public final float a;
    public final float b;

    public i(float f, float f2) {
        this.a = f;
        this.b = f2;
    }

    @Override // androidx.compose.ui.d
    public final long a(long j, long j2, androidx.compose.ui.unit.k kVar) {
        float f = (((int) (j2 >> 32)) - ((int) (j >> 32))) / 2.0f;
        float f2 = (((int) (j2 & 4294967295L)) - ((int) (j & 4294967295L))) / 2.0f;
        androidx.compose.ui.unit.k kVar2 = androidx.compose.ui.unit.k.a;
        float f3 = this.a;
        if (kVar != kVar2) {
            f3 *= -1;
        }
        float f4 = 1;
        return P5.b(Math.round((f3 + f4) * f), Math.round((f4 + this.b) * f2));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return Float.compare(this.a, iVar.a) == 0 && Float.compare(this.b, iVar.b) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.b) + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("BiasAlignment(horizontalBias=");
        sb.append(this.a);
        sb.append(", verticalBias=");
        return android.support.v4.media.session.a.p(sb, this.b, ')');
    }
}
