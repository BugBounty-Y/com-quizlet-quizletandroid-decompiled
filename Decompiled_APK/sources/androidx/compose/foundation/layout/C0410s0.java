package androidx.compose.foundation.layout;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.O5;

/* renamed from: androidx.compose.foundation.layout.s0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0410s0 extends androidx.compose.animation.h0 {
    public int o;
    public boolean p;

    @Override // androidx.compose.animation.h0
    public final long M0(androidx.compose.ui.layout.J j, long j2) {
        int iX = this.o == 1 ? j.X(androidx.compose.ui.unit.a.h(j2)) : j.b(androidx.compose.ui.unit.a.h(j2));
        if (iX < 0) {
            iX = 0;
        }
        if (iX >= 0) {
            return L5.m(0, SubsamplingScaleImageView.TILE_SIZE_AUTO, iX, iX);
        }
        O5.e("height(" + iX + ") must be >= 0");
        throw null;
    }

    @Override // androidx.compose.animation.h0
    public final boolean N0() {
        return this.p;
    }

    @Override // androidx.compose.animation.h0, androidx.compose.ui.node.InterfaceC0926w
    public final int f(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return this.o == 1 ? j.X(i) : j.b(i);
    }

    @Override // androidx.compose.animation.h0, androidx.compose.ui.node.InterfaceC0926w
    public final int i(androidx.compose.ui.node.O o, androidx.compose.ui.layout.J j, int i) {
        return this.o == 1 ? j.X(i) : j.b(i);
    }
}
