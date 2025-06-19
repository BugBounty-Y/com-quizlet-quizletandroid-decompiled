package assistantMode.grading;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class GradedAnswerMetadata$Companion {
    public static final /* synthetic */ GradedAnswerMetadata$Companion a = new GradedAnswerMetadata$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new kotlinx.serialization.e("assistantMode.grading.GradedAnswerMetadata", K.a(b.class), new kotlin.reflect.c[]{K.a(LocalGradedAnswerMetadata.class), K.a(SmartGradedAnswerMetadata.class)}, new KSerializer[]{LocalGradedAnswerMetadata$$serializer.INSTANCE, SmartGradedAnswerMetadata$$serializer.INSTANCE}, new Annotation[0]);
    }
}
