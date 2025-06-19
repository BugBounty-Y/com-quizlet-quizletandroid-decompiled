package assistantMode.refactored.types.flashcards;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class FlashcardsStep$Companion {
    public static final /* synthetic */ FlashcardsStep$Companion a = new FlashcardsStep$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new kotlinx.serialization.e("assistantMode.refactored.types.flashcards.FlashcardsStep", K.a(f.class), new kotlin.reflect.c[]{K.a(FlashcardsCycleSummary.class), K.a(FlashcardsQuestion.class), K.a(FlashcardsRoundSummary.class)}, new KSerializer[]{FlashcardsCycleSummary$$serializer.INSTANCE, FlashcardsQuestion$$serializer.INSTANCE, FlashcardsRoundSummary$$serializer.INSTANCE}, new Annotation[0]);
    }
}
