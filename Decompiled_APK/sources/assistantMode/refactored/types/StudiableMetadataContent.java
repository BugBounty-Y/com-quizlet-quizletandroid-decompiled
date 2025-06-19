package assistantMode.refactored.types;

import assistantMode.enums.q;
import java.lang.annotation.Annotation;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class StudiableMetadataContent {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c = {new C5048d(new kotlinx.serialization.e("assistantMode.refactored.types.StudiableMetadata", K.a(f.class), new kotlin.reflect.c[]{K.a(AlternativeQuestion.class), K.a(CardSideQuestionTypeRecommendation.class), K.a(FillInTheBlankMultipleChoiceQuestionStudiableMetadata.class), K.a(FillInTheBlankQuestionStudiableMetadata.class), K.a(MLMCQDistractorStudiableMetadata.class), K.a(MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata.class), K.a(ParsedMultipleChoiceQuestionStudiableMetadata.class)}, new KSerializer[]{AlternativeQuestion$$serializer.INSTANCE, CardSideQuestionTypeRecommendation$$serializer.INSTANCE, FillInTheBlankMultipleChoiceQuestionStudiableMetadata$$serializer.INSTANCE, FillInTheBlankQuestionStudiableMetadata$$serializer.INSTANCE, MLMCQDistractorStudiableMetadata$$serializer.INSTANCE, MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata$$serializer.INSTANCE, ParsedMultipleChoiceQuestionStudiableMetadata$$serializer.INSTANCE}, new Annotation[0]), 0), null};
    public final List a;
    public final q b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudiableMetadataContent$$serializer.INSTANCE;
        }
    }

    public StudiableMetadataContent(int i, List list, q qVar) {
        this.a = (i & 1) == 0 ? kotlin.collections.K.a : list;
        if ((i & 2) == 0) {
            this.b = q.d;
        } else {
            this.b = qVar;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableMetadataContent)) {
            return false;
        }
        StudiableMetadataContent studiableMetadataContent = (StudiableMetadataContent) obj;
        return Intrinsics.b(this.a, studiableMetadataContent.a) && this.b == studiableMetadataContent.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "StudiableMetadataContent(studiableMetadata=" + this.a + ", studiableMetadataStatus=" + this.b + ")";
    }

    public StudiableMetadataContent(List studiableMetadata, q studiableMetadataStatus) {
        Intrinsics.checkNotNullParameter(studiableMetadata, "studiableMetadata");
        Intrinsics.checkNotNullParameter(studiableMetadataStatus, "studiableMetadataStatus");
        this.a = studiableMetadata;
        this.b = studiableMetadataStatus;
    }
}
