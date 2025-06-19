package com.quizlet.features.flashcards.data;

import androidx.compose.animation.d0;
import com.quizlet.features.infra.models.flashcards.FlashcardSettings$FlashcardSettingsState;
import com.quizlet.generated.enums.G1;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h extends l {
    public final FlashcardSettings$FlashcardSettingsState a;
    public final long b;
    public final G1 c;
    public final int d;
    public final List e;

    public h(FlashcardSettings$FlashcardSettingsState currentState, long j, G1 studiableType, int i, List availableCardSides) {
        Intrinsics.checkNotNullParameter(currentState, "currentState");
        Intrinsics.checkNotNullParameter(studiableType, "studiableType");
        Intrinsics.checkNotNullParameter(availableCardSides, "availableCardSides");
        this.a = currentState;
        this.b = j;
        this.c = studiableType;
        this.d = i;
        this.e = availableCardSides;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && this.b == hVar.b && this.c == hVar.c && this.d == hVar.d && Intrinsics.b(this.e, hVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.b(this.d, (this.c.hashCode() + d0.d(this.a.hashCode() * 31, 31, this.b)) * 31, 31);
    }

    public final String toString() {
        return "Settings(currentState=" + this.a + ", studiableId=" + this.b + ", studiableType=" + this.c + ", selectedCardCount=" + this.d + ", availableCardSides=" + this.e + ")";
    }
}
