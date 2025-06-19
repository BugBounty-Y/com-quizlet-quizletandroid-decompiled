package assistantMode.refactored.types.flashcards;

import androidx.compose.animation.d0;
import assistantMode.refactored.types.RevealSelfAssessmentQuestion$$serializer;
import com.quizlet.shared.enums.s;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.C4927s;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.C5071z;
import kotlinx.serialization.internal.T;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardsState {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] h;
    public final List a;
    public final List b;
    public final List c;
    public final boolean d;
    public final C4927s e;
    public final FlashcardsModeProgress f;
    public final int g;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsState$$serializer.INSTANCE;
        }
    }

    static {
        RevealSelfAssessmentQuestion$$serializer revealSelfAssessmentQuestion$$serializer = RevealSelfAssessmentQuestion$$serializer.INSTANCE;
        h = new KSerializer[]{new C5048d(revealSelfAssessmentQuestion$$serializer, 0), new C5048d(revealSelfAssessmentQuestion$$serializer, 0), new C5048d(revealSelfAssessmentQuestion$$serializer, 0), null, new C5071z(new T(s.f, revealSelfAssessmentQuestion$$serializer, 1)), null, null};
    }

    public /* synthetic */ FlashcardsState(int i, List list, List list2, List list3, boolean z, C4927s c4927s, FlashcardsModeProgress flashcardsModeProgress, int i2) {
        if (127 != (i & 127)) {
            AbstractC5047c0.k(i, 127, FlashcardsState$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = list2;
        this.c = list3;
        this.d = z;
        this.e = c4927s;
        this.f = flashcardsModeProgress;
        this.g = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsState)) {
            return false;
        }
        FlashcardsState flashcardsState = (FlashcardsState) obj;
        return Intrinsics.b(this.a, flashcardsState.a) && Intrinsics.b(this.b, flashcardsState.b) && Intrinsics.b(this.c, flashcardsState.c) && this.d == flashcardsState.d && Intrinsics.b(this.e, flashcardsState.e) && Intrinsics.b(this.f, flashcardsState.f) && this.g == flashcardsState.g;
    }

    public final int hashCode() {
        return Integer.hashCode(this.g) + ((this.f.hashCode() + ((this.e.hashCode() + d0.g(d0.f(d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardsState(cardsRemainingInCurrentRound=");
        sb.append(this.a);
        sb.append(", cardsInNextRound=");
        sb.append(this.b);
        sb.append(", cardsStudiedInCurrentRound=");
        sb.append(this.c);
        sb.append(", hasActionAvailableToUndo=");
        sb.append(this.d);
        sb.append(", actionsAvailableToUndo=");
        sb.append(this.e);
        sb.append(", progress=");
        sb.append(this.f);
        sb.append(", shuffleRandomSeed=");
        return android.support.v4.media.session.a.r(sb, this.g, ")");
    }
}
