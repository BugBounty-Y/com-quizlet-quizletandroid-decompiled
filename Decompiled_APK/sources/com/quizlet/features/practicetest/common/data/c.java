package com.quizlet.features.practicetest.common.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements h {
    public final com.quizlet.features.practicetest.detail.viewmodel.g a;

    public c(com.quizlet.features.practicetest.detail.viewmodel.g onCtaButtonClicked) {
        Intrinsics.checkNotNullParameter(onCtaButtonClicked, "onCtaButtonClicked");
        this.a = onCtaButtonClicked;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && this.a.equals(((c) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "LoadErrorQuestionBank(onCtaButtonClicked=" + this.a + ")";
    }
}
