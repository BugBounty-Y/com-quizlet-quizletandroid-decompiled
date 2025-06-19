package com.airbnb.lottie.compose;

import androidx.compose.animation.C;
import androidx.compose.ui.layout.J;
import androidx.compose.ui.layout.L;
import androidx.compose.ui.layout.M;
import androidx.compose.ui.layout.W;
import androidx.compose.ui.node.InterfaceC0926w;
import com.google.android.gms.internal.mlkit_vision_barcode.L5;
import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k extends androidx.compose.ui.p implements InterfaceC0926w {
    public int n;
    public int o;

    @Override // androidx.compose.ui.node.InterfaceC0926w
    public final L h(M measure, J measurable, long j) {
        long jA;
        Intrinsics.checkNotNullParameter(measure, "$this$measure");
        Intrinsics.checkNotNullParameter(measurable, "measurable");
        long jI = L5.i(j, R5.a(this.n, this.o));
        if (androidx.compose.ui.unit.a.g(j) == Integer.MAX_VALUE && androidx.compose.ui.unit.a.h(j) != Integer.MAX_VALUE) {
            int i = (int) (jI >> 32);
            int i2 = (this.o * i) / this.n;
            jA = L5.a(i, i, i2, i2);
        } else if (androidx.compose.ui.unit.a.h(j) != Integer.MAX_VALUE || androidx.compose.ui.unit.a.g(j) == Integer.MAX_VALUE) {
            int i3 = (int) (jI >> 32);
            int i4 = (int) (jI & 4294967295L);
            jA = L5.a(i3, i3, i4, i4);
        } else {
            int i5 = (int) (jI & 4294967295L);
            int i6 = (this.n * i5) / this.o;
            jA = L5.a(i6, i6, i5, i5);
        }
        W wB = measurable.B(jA);
        return measure.n0(wB.a, wB.b, V.c(), new C(wB, 16));
    }
}
