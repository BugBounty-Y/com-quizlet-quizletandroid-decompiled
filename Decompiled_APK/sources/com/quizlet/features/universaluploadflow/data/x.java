package com.quizlet.features.universaluploadflow.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class x implements F {
    public final C4457f a;

    public x(C4457f flashcardsNavigationData) {
        Intrinsics.checkNotNullParameter(flashcardsNavigationData, "flashcardsNavigationData");
        this.a = flashcardsNavigationData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof x) && Intrinsics.b(this.a, ((x) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Flashcards(flashcardsNavigationData=" + this.a + ")";
    }
}
