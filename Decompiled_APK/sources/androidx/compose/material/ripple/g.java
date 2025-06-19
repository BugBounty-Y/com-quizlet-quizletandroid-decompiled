package androidx.compose.material.ripple;

import com.google.android.gms.internal.mlkit_vision_barcode.Q4;

/* loaded from: classes.dex */
public abstract class g {
    public static final float a = 10;

    public static final float a(androidx.compose.ui.unit.b bVar, boolean z, long j) {
        float fC = androidx.compose.ui.geometry.b.c(Q4.c(androidx.compose.ui.geometry.e.d(j), androidx.compose.ui.geometry.e.b(j))) / 2.0f;
        return z ? bVar.c0(a) + fC : fC;
    }
}
