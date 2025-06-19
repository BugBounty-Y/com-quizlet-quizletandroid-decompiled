package assistantMode.refactored.types.flashcards;

import assistantMode.types.FlashcardsStepMetadata;
import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class FlashcardsCycleSummary implements f {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] d = {new kotlinx.serialization.e("assistantMode.refactored.types.flashcards.FlashcardsAction", K.a(a.class), new kotlin.reflect.c[]{K.a(FlashcardsBeginRoundActionClass.class), K.a(FlashcardsSubmitAction.class), K.a(FlashcardsUndoAction.class)}, new KSerializer[]{FlashcardsBeginRoundActionClass$$serializer.INSTANCE, FlashcardsSubmitAction$$serializer.INSTANCE, FlashcardsUndoAction$$serializer.INSTANCE}, new Annotation[0]), null, null};
    public final a a;
    public final FlashcardsModeProgress b;
    public final FlashcardsStepMetadata c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FlashcardsCycleSummary$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FlashcardsCycleSummary(int i, a aVar, FlashcardsModeProgress flashcardsModeProgress, FlashcardsStepMetadata flashcardsStepMetadata) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, FlashcardsCycleSummary$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = aVar;
        this.b = flashcardsModeProgress;
        this.c = flashcardsStepMetadata;
    }

    @Override // assistantMode.refactored.types.flashcards.f
    public final FlashcardsModeProgress a() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FlashcardsCycleSummary)) {
            return false;
        }
        FlashcardsCycleSummary flashcardsCycleSummary = (FlashcardsCycleSummary) obj;
        return Intrinsics.b(this.a, flashcardsCycleSummary.a) && Intrinsics.b(this.b, flashcardsCycleSummary.b) && Intrinsics.b(this.c, flashcardsCycleSummary.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "FlashcardsCycleSummary(lastAction=" + this.a + ", progress=" + this.b + ", metadata=" + this.c + ")";
    }

    public FlashcardsCycleSummary(a lastAction, FlashcardsModeProgress progress, FlashcardsStepMetadata metadata) {
        Intrinsics.checkNotNullParameter(lastAction, "lastAction");
        Intrinsics.checkNotNullParameter(progress, "progress");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = lastAction;
        this.b = progress;
        this.c = metadata;
    }
}
