package androidx.compose.foundation;

import com.google.android.gms.internal.mlkit_vision_barcode.Q4;

/* loaded from: classes.dex */
public final class H0 extends F0 {
    @Override // androidx.compose.foundation.F0, androidx.compose.foundation.D0
    public final void a(long j, long j2) {
        if (!Float.isNaN(Float.NaN)) {
            this.a.setZoom(Float.NaN);
        }
        if (Q4.h(j2)) {
            this.a.show(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j), androidx.compose.ui.geometry.b.d(j2), androidx.compose.ui.geometry.b.e(j2));
        } else {
            this.a.show(androidx.compose.ui.geometry.b.d(j), androidx.compose.ui.geometry.b.e(j));
        }
    }
}
