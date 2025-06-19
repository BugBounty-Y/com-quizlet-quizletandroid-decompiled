package com.quizlet.explanations.myexplanations.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends f {
    public final com.quizlet.qutils.string.f a;

    public b(com.quizlet.qutils.string.f emptyHeader) {
        Intrinsics.checkNotNullParameter(emptyHeader, "emptyHeader");
        this.a = emptyHeader;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && this.a.equals(((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Empty(emptyHeader=" + this.a + ")";
    }
}
