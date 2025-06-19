package com.quizlet.features.practicetest.takingtest;

import com.quizlet.quizletandroid.R;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends e {
    public final h b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(h onClick) {
        super(R.string.practice_test_taking_submit_button);
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
        return (obj instanceof d) && this.b.equals(((d) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return "Submit(onClick=" + this.b + ")";
    }
}
