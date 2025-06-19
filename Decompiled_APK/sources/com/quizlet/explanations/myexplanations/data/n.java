package com.quizlet.explanations.myexplanations.data;

import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class n extends o {
    public final TextbookSetUpState a;

    public n(TextbookSetUpState setUpState) {
        Intrinsics.checkNotNullParameter(setUpState, "setUpState");
        this.a = setUpState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Textbook(setUpState=" + this.a + ")";
    }
}
