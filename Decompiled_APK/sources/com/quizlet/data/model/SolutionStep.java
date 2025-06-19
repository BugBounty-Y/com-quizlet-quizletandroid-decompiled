package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class SolutionStep {
    public final boolean a;
    public final int b;
    public final List c;

    public SolutionStep(boolean z, int i, List columns) {
        Intrinsics.checkNotNullParameter(columns, "columns");
        this.a = z;
        this.b = i;
        this.c = columns;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SolutionStep)) {
            return false;
        }
        SolutionStep solutionStep = (SolutionStep) obj;
        return this.a == solutionStep.a && this.b == solutionStep.b && Intrinsics.b(this.c, solutionStep.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + androidx.compose.animation.d0.b(this.b, Boolean.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SolutionStep(isResult=");
        sb.append(this.a);
        sb.append(", stepNumber=");
        sb.append(this.b);
        sb.append(", columns=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }
}
