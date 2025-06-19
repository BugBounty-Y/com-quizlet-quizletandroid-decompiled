package com.quizlet.features.flashcards.autoplay;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class q implements b {
    public final com.quizlet.features.flashcards.data.b a;
    public final boolean b;
    public final com.quizlet.features.flashcards.engine.h c;

    public q(com.quizlet.features.flashcards.data.b firstCard, boolean z, com.quizlet.features.flashcards.engine.h engineManager) {
        Intrinsics.checkNotNullParameter(firstCard, "firstCard");
        Intrinsics.checkNotNullParameter(engineManager, "engineManager");
        this.a = firstCard;
        this.b = z;
        this.c = engineManager;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return Intrinsics.b(this.a, qVar.a) && this.b == qVar.b && Intrinsics.b(this.c, qVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "StartAutoplay(firstCard=" + this.a + ", audioEnabled=" + this.b + ", engineManager=" + this.c + ")";
    }
}
