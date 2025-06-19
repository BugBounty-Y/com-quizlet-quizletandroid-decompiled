package assistantMode.refactored.types.flashcards;

import androidx.compose.animation.d0;
import assistantMode.refactored.types.TotalProgress;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardsModeProgress {

    @NotNull
    public static final Companion Companion = new Companion();
    public final TotalProgress a;
    public final int b;
    public final FlashcardsProgressStats c;
    public final FlashcardsProgressStats d;
    public final FlashcardsProgressStats e;
    public final FlashcardsRoundProgress f;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsModeProgress$$serializer.INSTANCE;
        }
    }

    public FlashcardsModeProgress(int i, TotalProgress totalProgress, int i2, FlashcardsProgressStats flashcardsProgressStats, FlashcardsProgressStats flashcardsProgressStats2, FlashcardsProgressStats flashcardsProgressStats3, FlashcardsRoundProgress flashcardsRoundProgress) {
        if (31 != (i & 31)) {
            AbstractC5047c0.k(i, 31, FlashcardsModeProgress$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = totalProgress;
        this.b = i2;
        this.c = flashcardsProgressStats;
        this.d = flashcardsProgressStats2;
        this.e = flashcardsProgressStats3;
        if ((i & 32) != 0) {
            this.f = flashcardsRoundProgress;
            return;
        }
        boolean zA = flashcardsProgressStats3.a();
        boolean zA2 = flashcardsProgressStats2.a();
        int i3 = flashcardsProgressStats3.a;
        int i4 = flashcardsProgressStats3.b;
        int i5 = flashcardsProgressStats3.c;
        this.f = new FlashcardsRoundProgress(zA, zA2, i3, flashcardsProgressStats2.a, i4, flashcardsProgressStats2.b, i5, (i3 + i4) / i5);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsModeProgress)) {
            return false;
        }
        FlashcardsModeProgress flashcardsModeProgress = (FlashcardsModeProgress) obj;
        return Intrinsics.b(this.a, flashcardsModeProgress.a) && this.b == flashcardsModeProgress.b && Intrinsics.b(this.c, flashcardsModeProgress.c) && Intrinsics.b(this.d, flashcardsModeProgress.d) && Intrinsics.b(this.e, flashcardsModeProgress.e) && Intrinsics.b(this.f, flashcardsModeProgress.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + d0.b(this.b, this.a.hashCode() * 31, 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "FlashcardsModeProgress(totalProgress=" + this.a + ", currentRound=" + this.b + ", total=" + this.c + ", cycle=" + this.d + ", round=" + this.e + ", roundProgress=" + this.f + ")";
    }

    public FlashcardsModeProgress(TotalProgress totalProgress, int i, FlashcardsProgressStats total, FlashcardsProgressStats cycle, FlashcardsProgressStats round) {
        boolean zA = round.a();
        boolean zA2 = cycle.a();
        int i2 = round.a;
        int i3 = round.b;
        int i4 = round.c;
        FlashcardsRoundProgress roundProgress = new FlashcardsRoundProgress(zA, zA2, i2, cycle.a, i3, cycle.b, i4, (i2 + i3) / i4);
        Intrinsics.checkNotNullParameter(totalProgress, "totalProgress");
        Intrinsics.checkNotNullParameter(total, "total");
        Intrinsics.checkNotNullParameter(cycle, "cycle");
        Intrinsics.checkNotNullParameter(round, "round");
        Intrinsics.checkNotNullParameter(roundProgress, "roundProgress");
        this.a = totalProgress;
        this.b = i;
        this.c = total;
        this.d = cycle;
        this.e = round;
        this.f = roundProgress;
    }
}
