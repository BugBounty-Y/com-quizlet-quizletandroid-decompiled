package assistantMode.types;

import assistantMode.grading.LocalGradedAnswerMetadata;
import assistantMode.grading.LocalGradedAnswerMetadata$$serializer;
import assistantMode.grading.SmartGradedAnswerMetadata;
import assistantMode.grading.SmartGradedAnswerMetadata$$serializer;
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
public final class GradedAnswer {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] e = {null, null, null, new kotlinx.serialization.e("assistantMode.grading.GradedAnswerMetadata", K.a(assistantMode.grading.b.class), new kotlin.reflect.c[]{K.a(LocalGradedAnswerMetadata.class), K.a(SmartGradedAnswerMetadata.class)}, new KSerializer[]{LocalGradedAnswerMetadata$$serializer.INSTANCE, SmartGradedAnswerMetadata$$serializer.INSTANCE}, new Annotation[0])};
    public final boolean a;
    public final Feedback b;
    public final AssistantGradingSettingsSuggestion c;
    public final assistantMode.grading.b d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return GradedAnswer$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ GradedAnswer(int i, boolean z, Feedback feedback, AssistantGradingSettingsSuggestion assistantGradingSettingsSuggestion, assistantMode.grading.b bVar) {
        if (11 != (i & 11)) {
            AbstractC5047c0.k(i, 11, GradedAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = z;
        this.b = feedback;
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = assistantGradingSettingsSuggestion;
        }
        this.d = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GradedAnswer)) {
            return false;
        }
        GradedAnswer gradedAnswer = (GradedAnswer) obj;
        return this.a == gradedAnswer.a && Intrinsics.b(this.b, gradedAnswer.b) && Intrinsics.b(this.c, gradedAnswer.c) && Intrinsics.b(this.d, gradedAnswer.d);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (Boolean.hashCode(this.a) * 31)) * 31;
        AssistantGradingSettingsSuggestion assistantGradingSettingsSuggestion = this.c;
        return this.d.hashCode() + ((iHashCode + (assistantGradingSettingsSuggestion == null ? 0 : assistantGradingSettingsSuggestion.hashCode())) * 31);
    }

    public final String toString() {
        return "GradedAnswer(isCorrect=" + this.a + ", feedback=" + this.b + ", gradingSettingsSuggestion=" + this.c + ", metadata=" + this.d + ")";
    }

    public GradedAnswer(boolean z, Feedback feedback, AssistantGradingSettingsSuggestion assistantGradingSettingsSuggestion, assistantMode.grading.b metadata) {
        Intrinsics.checkNotNullParameter(feedback, "feedback");
        Intrinsics.checkNotNullParameter(metadata, "metadata");
        this.a = z;
        this.b = feedback;
        this.c = assistantGradingSettingsSuggestion;
        this.d = metadata;
    }
}
