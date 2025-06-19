package assistantMode.refactored.types.flashcards;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardsRoundProgress {

    @NotNull
    public static final Companion Companion = new Companion();
    public final boolean a;
    public final boolean b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final int g;
    public final double h;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsRoundProgress$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FlashcardsRoundProgress(int i, boolean z, boolean z2, int i2, int i3, int i4, int i5, int i6, double d) {
        if (255 != (i & 255)) {
            AbstractC5047c0.k(i, 255, FlashcardsRoundProgress$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = z;
        this.b = z2;
        this.c = i2;
        this.d = i3;
        this.e = i4;
        this.f = i5;
        this.g = i6;
        this.h = d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsRoundProgress)) {
            return false;
        }
        FlashcardsRoundProgress flashcardsRoundProgress = (FlashcardsRoundProgress) obj;
        return this.a == flashcardsRoundProgress.a && this.b == flashcardsRoundProgress.b && this.c == flashcardsRoundProgress.c && this.d == flashcardsRoundProgress.d && this.e == flashcardsRoundProgress.e && this.f == flashcardsRoundProgress.f && this.g == flashcardsRoundProgress.g && Double.compare(this.h, flashcardsRoundProgress.h) == 0;
    }

    public final int hashCode() {
        return Double.hashCode(this.h) + d0.b(this.g, d0.b(this.f, d0.b(this.e, d0.b(this.d, d0.b(this.c, d0.g(Boolean.hashCode(this.a) * 31, 31, this.b), 31), 31), 31), 31), 31);
    }

    public final String toString() {
        return "FlashcardsRoundProgress(isRoundComplete=" + this.a + ", isCycleComplete=" + this.b + ", numCardsCompleted=" + this.c + ", totalNumCardsCompleted=" + this.d + ", numCardsMovedToNextCycle=" + this.e + ", totalNumCardsMovedToNextCycle=" + this.f + ", numCards=" + this.g + ", roundProgressPercent=" + this.h + ")";
    }

    public FlashcardsRoundProgress(boolean z, boolean z2, int i, int i2, int i3, int i4, int i5, double d) {
        this.a = z;
        this.b = z2;
        this.c = i;
        this.d = i2;
        this.e = i3;
        this.f = i4;
        this.g = i5;
        this.h = d;
    }
}
