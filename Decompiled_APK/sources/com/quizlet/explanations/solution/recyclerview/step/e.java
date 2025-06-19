package com.quizlet.explanations.solution.recyclerview.step;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e implements com.quizlet.baserecyclerview.a {
    public final boolean a;
    public final int b;
    public final int c;
    public final kotlinx.collections.immutable.b d;
    public final int e;
    public final com.quizlet.explanations.solution.fragments.b f;
    public final boolean g;
    public final String h;
    public final boolean i;

    public e(boolean z, int i, int i2, kotlinx.collections.immutable.b columns, int i3, com.quizlet.explanations.solution.fragments.b onImageLongClick, boolean z2) {
        Intrinsics.checkNotNullParameter(columns, "columns");
        Intrinsics.checkNotNullParameter(onImageLongClick, "onImageLongClick");
        this.a = z;
        this.b = i;
        this.c = i2;
        this.d = columns;
        this.e = i3;
        this.f = onImageLongClick;
        this.g = z2;
        this.h = d0.p("solution_step_", i3, "_", i);
        this.i = i == 1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a == eVar.a && this.b == eVar.b && this.c == eVar.c && Intrinsics.b(this.d, eVar.d) && this.e == eVar.e && this.f.equals(eVar.f) && this.g == eVar.g;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return this.h;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.g) + ((this.f.hashCode() + d0.b(this.e, (this.d.hashCode() + d0.b(this.c, d0.b(this.b, Boolean.hashCode(this.a) * 31, 31), 31)) * 31, 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SolutionStepItem(isResult=");
        sb.append(this.a);
        sb.append(", stepNumber=");
        sb.append(this.b);
        sb.append(", stepCountTotal=");
        sb.append(this.c);
        sb.append(", columns=");
        sb.append(this.d);
        sb.append(", solutionNum=");
        sb.append(this.e);
        sb.append(", onImageLongClick=");
        sb.append(this.f);
        sb.append(", isBlurred=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}
