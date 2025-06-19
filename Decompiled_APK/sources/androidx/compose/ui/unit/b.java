package androidx.compose.ui.unit;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.google.android.gms.internal.mlkit_vision_barcode.S5;
import com.google.android.gms.internal.mlkit_vision_barcode.T4;

/* loaded from: classes.dex */
public interface b {
    default long K(float f) {
        return r(R(f));
    }

    default float O(int i) {
        return i / a();
    }

    default float R(float f) {
        return f / a();
    }

    float Z();

    float a();

    default float c0(float f) {
        return a() * f;
    }

    default int j0(long j) {
        return Math.round(v0(j));
    }

    default int m0(float f) {
        float fC0 = c0(f);
        return Float.isInfinite(fC0) ? SubsamplingScaleImageView.TILE_SIZE_AUTO : Math.round(fC0);
    }

    default long q0(long j) {
        if (j != 9205357640488583168L) {
            return T4.a(c0(g.b(j)), c0(g.a(j)));
        }
        return 9205357640488583168L;
    }

    default long r(float f) {
        float[] fArr = androidx.compose.ui.unit.fontscaling.b.a;
        if (!(Z() >= 1.03f)) {
            return S5.i(4294967296L, f / Z());
        }
        androidx.compose.ui.unit.fontscaling.a aVarA = androidx.compose.ui.unit.fontscaling.b.a(Z());
        return S5.i(4294967296L, aVarA != null ? aVarA.a(f) : f / Z());
    }

    default long s(long j) {
        if (j != 9205357640488583168L) {
            return N5.c(R(androidx.compose.ui.geometry.e.d(j)), R(androidx.compose.ui.geometry.e.b(j)));
        }
        return 9205357640488583168L;
    }

    default float v0(long j) {
        if (n.a(m.b(j), 4294967296L)) {
            return c0(y(j));
        }
        throw new IllegalStateException("Only Sp can convert to Px");
    }

    default float y(long j) {
        float fC;
        float fZ;
        if (!n.a(m.b(j), 4294967296L)) {
            throw new IllegalStateException("Only Sp can convert to Px");
        }
        float[] fArr = androidx.compose.ui.unit.fontscaling.b.a;
        if (Z() >= 1.03f) {
            androidx.compose.ui.unit.fontscaling.a aVarA = androidx.compose.ui.unit.fontscaling.b.a(Z());
            fC = m.c(j);
            if (aVarA != null) {
                return aVarA.b(fC);
            }
            fZ = Z();
        } else {
            fC = m.c(j);
            fZ = Z();
        }
        return fZ * fC;
    }
}
