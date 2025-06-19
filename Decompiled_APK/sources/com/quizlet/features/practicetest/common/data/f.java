package com.quizlet.features.practicetest.common.data;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements h {
    public final Function0 a;

    public f(Function0 onCtaButtonClicked) {
        Intrinsics.checkNotNullParameter(onCtaButtonClicked, "onCtaButtonClicked");
        this.a = onCtaButtonClicked;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "UnsupportedQuestionBank(onCtaButtonClicked=" + this.a + ")";
    }
}
