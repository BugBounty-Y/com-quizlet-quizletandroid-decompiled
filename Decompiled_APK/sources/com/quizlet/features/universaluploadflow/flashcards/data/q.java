package com.quizlet.features.universaluploadflow.flashcards.data;

import com.quizlet.data.model.m2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q implements s {
    public final m2 a;

    public q(m2 source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
    }

    @Override // com.quizlet.features.universaluploadflow.flashcards.data.s
    public final boolean a() {
        return false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof q) && this.a == ((q) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "GeneratingContent(source=" + this.a + ")";
    }
}
