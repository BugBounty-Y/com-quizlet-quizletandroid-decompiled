package com.quizlet.features.match.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class A extends C {
    public final AbstractC4353i a;

    public A(AbstractC4353i boardData) {
        Intrinsics.checkNotNullParameter(boardData, "boardData");
        this.a = boardData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof A) && Intrinsics.b(this.a, ((A) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Board(boardData=" + this.a + ")";
    }
}
