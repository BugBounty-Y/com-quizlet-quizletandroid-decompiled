package com.quizlet.search.data.term;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends h {
    public final a a;

    public f(a termSearchUiModel) {
        Intrinsics.checkNotNullParameter(termSearchUiModel, "termSearchUiModel");
        this.a = termSearchUiModel;
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
        return "Loaded(termSearchUiModel=" + this.a + ")";
    }
}
