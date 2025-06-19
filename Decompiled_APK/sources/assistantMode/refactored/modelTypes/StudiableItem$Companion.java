package assistantMode.refactored.modelTypes;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.e;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class StudiableItem$Companion {
    public static final /* synthetic */ StudiableItem$Companion a = new StudiableItem$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new e("assistantMode.refactored.modelTypes.StudiableItem", K.a(d.class), new kotlin.reflect.c[]{K.a(Card.class), K.a(CustomMultipleChoiceQuestion.class)}, new KSerializer[]{Card$$serializer.INSTANCE, CustomMultipleChoiceQuestion$$serializer.INSTANCE}, new Annotation[0]);
    }
}
