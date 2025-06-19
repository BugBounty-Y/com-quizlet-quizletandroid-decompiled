package assistantMode.refactored.types.flashcards;

import androidx.compose.animation.d0;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b {
    public final ArrayList a;
    public final ArrayList b;
    public final ArrayList c;
    public final ArrayList d;
    public final int e;
    public final ArrayList f;
    public final int g;
    public final kotlin.random.g h;

    public b(ArrayList allFlashcards, ArrayList flashcardsStudiedInCycle, ArrayList flashcardsRemainingInCycle, ArrayList flashcardsInNextCycle, int i, ArrayList arrayList, int i2, kotlin.random.g random) {
        Intrinsics.checkNotNullParameter(allFlashcards, "allFlashcards");
        Intrinsics.checkNotNullParameter(flashcardsStudiedInCycle, "flashcardsStudiedInCycle");
        Intrinsics.checkNotNullParameter(flashcardsRemainingInCycle, "flashcardsRemainingInCycle");
        Intrinsics.checkNotNullParameter(flashcardsInNextCycle, "flashcardsInNextCycle");
        Intrinsics.checkNotNullParameter(random, "random");
        this.a = allFlashcards;
        this.b = flashcardsStudiedInCycle;
        this.c = flashcardsRemainingInCycle;
        this.d = flashcardsInNextCycle;
        this.e = i;
        this.f = arrayList;
        this.g = i2;
        this.h = random;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a.equals(bVar.a) && this.b.equals(bVar.b) && this.c.equals(bVar.c) && this.d.equals(bVar.d) && this.e == bVar.e && Intrinsics.b(this.f, bVar.f) && this.g == bVar.g && this.h.equals(bVar.h);
    }

    public final int hashCode() {
        int iB = d0.b(this.e, d0.h(this.d, d0.h(this.c, d0.h(this.b, this.a.hashCode() * 31, 31), 31), 31), 31);
        ArrayList arrayList = this.f;
        return this.h.hashCode() + d0.b(this.g, (iB + (arrayList == null ? 0 : arrayList.hashCode())) * 31, 31);
    }

    public final String toString() {
        return "FlashcardsInitialState(allFlashcards=" + this.a + ", flashcardsStudiedInCycle=" + this.b + ", flashcardsRemainingInCycle=" + this.c + ", flashcardsInNextCycle=" + this.d + ", numberOfFlashcardsInCycle=" + this.e + ", flashcardsStudiedInRound=" + this.f + ", currentRound=" + this.g + ", random=" + this.h + ")";
    }
}
