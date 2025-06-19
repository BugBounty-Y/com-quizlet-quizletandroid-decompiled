package androidx.compose.foundation.text;

import androidx.compose.ui.layout.InterfaceC0901w;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Y implements InterfaceC0901w {
    public final I0 b;
    public final int c;
    public final androidx.compose.ui.text.input.I d;
    public final Function0 e;

    public Y(I0 i0, int i, androidx.compose.ui.text.input.I i2, Function0 function0) {
        this.b = i0;
        this.c = i;
        this.d = i2;
        this.e = function0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Y)) {
            return false;
        }
        Y y = (Y) obj;
        return Intrinsics.b(this.b, y.b) && this.c == y.c && Intrinsics.b(this.d, y.d) && Intrinsics.b(this.e, y.e);
    }

    @Override // androidx.compose.ui.layout.InterfaceC0901w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        long j3;
        if (j.z(androidx.compose.ui.unit.a.g(j2)) < androidx.compose.ui.unit.a.h(j2)) {
            j3 = j2;
        } else {
            j3 = j2;
            j2 = androidx.compose.ui.unit.a.a(j3, 0, SubsamplingScaleImageView.TILE_SIZE_AUTO, 0, 0, 13);
        }
        androidx.compose.ui.layout.W wB = j.B(j2);
        int iMin = Math.min(wB.a, androidx.compose.ui.unit.a.h(j3));
        return m.n0(iMin, wB.b, kotlin.collections.V.c(), new X(iMin, 0, m, this, wB));
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + androidx.compose.animation.d0.b(this.c, this.b.hashCode() * 31, 31)) * 31);
    }

    public final String toString() {
        return "HorizontalScrollLayoutModifier(scrollerPosition=" + this.b + ", cursorOffset=" + this.c + ", transformedText=" + this.d + ", textLayoutResultProvider=" + this.e + ')';
    }
}
