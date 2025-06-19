package com.quizlet.assembly.widgets.progress;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c {
    public final int a;
    public final int b;
    public final e c;

    public c(int i, int i2, e progressVariant) {
        Intrinsics.checkNotNullParameter(progressVariant, "progressVariant");
        this.a = i;
        this.b = i2;
        this.c = progressVariant;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && this.b == cVar.b && this.c == cVar.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        return "ProgressViewProgress(description=" + this.a + ", progressValue=" + this.b + ", progressVariant=" + this.c + ")";
    }
}
