package androidx.compose.foundation.layout;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;

/* renamed from: androidx.compose.foundation.layout.t0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0412t0 extends androidx.compose.animation.h0 {
    public int o;
    public boolean p;

    @Override // androidx.compose.animation.h0
    public final long M0(androidx.compose.ui.layout.J j, long j2) {
        int iX = this.o == 1 ? j.x(androidx.compose.ui.unit.a.g(j2)) : j.z(androidx.compose.ui.unit.a.g(j2));
        if (iX < 0) {
            iX = 0;
        }
        if (iX >= 0) {
            return L5.m(iX, iX, 0, SubsamplingScaleImageView.TILE_SIZE_AUTO);
        }
        O5.e("width(" + iX + ") must be >= 0");
        throw null;
    }

    @Override // androidx.compose.animation.h0
    public final boolean N0() {
        return this.p;
    }

    @Override // androidx.compose.animation.h0, androidx.compose.ui.node.InterfaceC0926w
    public final int b(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return this.o == 1 ? j.x(i) : j.z(i);
    }

    @Override // androidx.compose.animation.h0, androidx.compose.ui.node.InterfaceC0926w
    public final int c(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return this.o == 1 ? j.x(i) : j.z(i);
    }
}
