package com.airbnb.lottie.compose;

import androidx.compose.ui.node.T;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class LottieAnimationSizeElement extends T {
    public final int b;
    public final int c;

    public LottieAnimationSizeElement(int i, int i2) {
        this.b = i;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LottieAnimationSizeElement)) {
            return false;
        }
        LottieAnimationSizeElement lottieAnimationSizeElement = (LottieAnimationSizeElement) obj;
        return this.b == lottieAnimationSizeElement.b && this.c == lottieAnimationSizeElement.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + (Integer.hashCode(this.b) * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        k kVar = new k();
        kVar.n = this.b;
        kVar.o = this.c;
        return kVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        k node = (k) pVar;
        Intrinsics.checkNotNullParameter(node, "node");
        node.n = this.b;
        node.o = this.c;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LottieAnimationSizeElement(width=");
        sb.append(this.b);
        sb.append(", height=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
