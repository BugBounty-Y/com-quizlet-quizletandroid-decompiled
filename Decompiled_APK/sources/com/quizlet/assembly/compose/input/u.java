package com.quizlet.assembly.compose.input;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class u implements w {
    public final androidx.compose.ui.graphics.painter.b a;

    public u(androidx.compose.ui.graphics.painter.b painter) {
        Intrinsics.checkNotNullParameter(painter, "painter");
        this.a = painter;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof u) && Intrinsics.b(this.a, ((u) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Image(painter=" + this.a + ")";
    }
}
