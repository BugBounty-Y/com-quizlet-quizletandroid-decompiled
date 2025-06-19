package com.quizlet.explanations.solution.viewmodel;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e {
    public final List a;
    public final boolean b;

    public e(List items, boolean z) {
        Intrinsics.checkNotNullParameter(items, "items");
        this.a = items;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && this.b == eVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SolutionStepItemState(items=");
        sb.append(this.a);
        sb.append(", shouldSmoothScrollToLastItem=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
