package androidx.compose.foundation.text;

import androidx.compose.ui.layout.InterfaceC0901w;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class S0 implements InterfaceC0901w {
    public final I0 b;
    public final int c;
    public final androidx.compose.ui.text.input.I d;
    public final Function0 e;

    public S0(I0 i0, int i, androidx.compose.ui.text.input.I i2, Function0 function0) {
        this.b = i0;
        this.c = i;
        this.d = i2;
        this.e = function0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof S0)) {
            return false;
        }
        S0 s0 = (S0) obj;
        return Intrinsics.b(this.b, s0.b) && this.c == s0.c && Intrinsics.b(this.d, s0.d) && Intrinsics.b(this.e, s0.e);
    }

    @Override // androidx.compose.ui.layout.InterfaceC0901w
    public final androidx.compose.ui.layout.L h(androidx.compose.ui.layout.M m, androidx.compose.ui.layout.J j, long j2) {
        androidx.compose.ui.layout.W wB = j.B(androidx.compose.ui.unit.a.a(j2, 0, 0, 0, SubsamplingScaleImageView.TILE_SIZE_AUTO, 7));
        int iMin = Math.min(wB.b, androidx.compose.ui.unit.a.g(j2));
        return m.n0(wB.a, iMin, kotlin.collections.V.c(), new X(iMin, 1, m, this, wB));
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + androidx.compose.animation.d0.b(this.c, this.b.hashCode() * 31, 31)) * 31);
    }

    public final String toString() {
        return "VerticalScrollLayoutModifier(scrollerPosition=" + this.b + ", cursorOffset=" + this.c + ", transformedText=" + this.d + ", textLayoutResultProvider=" + this.e + ')';
    }
}
