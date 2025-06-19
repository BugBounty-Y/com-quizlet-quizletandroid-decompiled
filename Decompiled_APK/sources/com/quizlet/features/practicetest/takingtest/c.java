package com.quizlet.features.practicetest.takingtest;

import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends e {
    public final com.quizlet.features.practicetest.detail.m b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.quizlet.features.practicetest.detail.m onClick) {
        super(R.string.practice_test_taking_next_button);
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        this.b = onClick;
    }

    @Override // com.quizlet.features.practicetest.takingtest.e
    public final Function0 a() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && this.b.equals(((c) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return "Next(onClick=" + this.b + ")";
    }
}
