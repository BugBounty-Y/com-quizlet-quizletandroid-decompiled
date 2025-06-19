package assistantMode.refactored.types.flashcards;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class FlashcardsAction$Companion {
    public static final /* synthetic */ FlashcardsAction$Companion a = new FlashcardsAction$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new kotlinx.serialization.e("assistantMode.refactored.types.flashcards.FlashcardsAction", K.a(a.class), new kotlin.reflect.c[]{K.a(FlashcardsBeginRoundActionClass.class), K.a(FlashcardsSubmitAction.class), K.a(FlashcardsUndoAction.class)}, new KSerializer[]{FlashcardsBeginRoundActionClass$$serializer.INSTANCE, FlashcardsSubmitAction$$serializer.INSTANCE, FlashcardsUndoAction$$serializer.INSTANCE}, new Annotation[0]);
    }
}
