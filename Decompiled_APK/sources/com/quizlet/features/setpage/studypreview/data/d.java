package com.quizlet.features.setpage.studypreview.data;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends e {
    public final Object a;

    public d(List flashcards) {
        Intrinsics.checkNotNullParameter(flashcards, "flashcards");
        this.a = flashcards;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("Populated(flashcards="), this.a, ")");
    }
}
