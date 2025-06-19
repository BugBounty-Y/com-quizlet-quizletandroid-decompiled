package assistantMode.types;

import assistantMode.enums.StudiableMetadataType$Companion;
import assistantMode.refactored.types.MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o extends E {
    public final MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata a;
    public final C1457d b;

    public o(MultipleChoiceSelectAllThatApplyQuestionStudiableMetadata multipleChoiceSelectAllThatApplyQuestionStudiableMetadata, C1457d cardEdge) {
        Intrinsics.checkNotNullParameter(multipleChoiceSelectAllThatApplyQuestionStudiableMetadata, "multipleChoiceSelectAllThatApplyQuestionStudiableMetadata");
        Intrinsics.checkNotNullParameter(cardEdge, "cardEdge");
        this.a = multipleChoiceSelectAllThatApplyQuestionStudiableMetadata;
        this.b = cardEdge;
        StudiableMetadataType$Companion studiableMetadataType$Companion = assistantMode.enums.s.Companion;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return Intrinsics.b(this.a, oVar.a) && Intrinsics.b(this.b, oVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "MultipleChoiceSelectAllThatApplyQuestionConfig(multipleChoiceSelectAllThatApplyQuestionStudiableMetadata=" + this.a + ", cardEdge=" + this.b + ")";
    }
}
