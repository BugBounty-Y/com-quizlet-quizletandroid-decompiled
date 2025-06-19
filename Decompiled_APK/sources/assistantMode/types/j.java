package assistantMode.types;

import assistantMode.enums.StudiableMetadataType$Companion;
import assistantMode.refactored.types.FillInTheBlankQuestionStudiableMetadata;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j extends E {
    public final FillInTheBlankQuestionStudiableMetadata a;
    public final C1457d b;

    public j(FillInTheBlankQuestionStudiableMetadata fillInTheBlankQuestionStudiableMetadata, C1457d cardEdge) {
        Intrinsics.checkNotNullParameter(fillInTheBlankQuestionStudiableMetadata, "fillInTheBlankQuestionStudiableMetadata");
        Intrinsics.checkNotNullParameter(cardEdge, "cardEdge");
        this.a = fillInTheBlankQuestionStudiableMetadata;
        this.b = cardEdge;
        StudiableMetadataType$Companion studiableMetadataType$Companion = assistantMode.enums.s.Companion;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return Intrinsics.b(this.a, jVar.a) && Intrinsics.b(this.b, jVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "FillInTheBlankQuestionConfig(fillInTheBlankQuestionStudiableMetadata=" + this.a + ", cardEdge=" + this.b + ")";
    }
}
