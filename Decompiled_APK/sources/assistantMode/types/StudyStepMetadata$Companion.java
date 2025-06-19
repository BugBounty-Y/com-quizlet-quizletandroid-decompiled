package assistantMode.types;

import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class StudyStepMetadata$Companion {
    public static final /* synthetic */ StudyStepMetadata$Companion a = new StudyStepMetadata$Companion();

    @NotNull
    public final KSerializer serializer() {
        return new kotlinx.serialization.e("assistantMode.types.StudyStepMetadata", K.a(F.class), new kotlin.reflect.c[]{K.a(CheckpointMetadata.class), K.a(FlashcardsStepMetadata.class), K.a(PaywallMetadata.class), K.a(QuestionMetadata.class), K.a(TestGeneratorOutputMetadata.class)}, new KSerializer[]{CheckpointMetadata$$serializer.INSTANCE, FlashcardsStepMetadata$$serializer.INSTANCE, PaywallMetadata$$serializer.INSTANCE, QuestionMetadata$$serializer.INSTANCE, TestGeneratorOutputMetadata$$serializer.INSTANCE}, new Annotation[0]);
    }
}
