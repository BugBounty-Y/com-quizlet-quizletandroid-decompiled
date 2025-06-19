package assistantMode.types;

import assistantMode.enums.StudiableMetadataType$Companion;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i extends p {
    public final ArrayList a;
    public final C1457d b;

    public i(ArrayList fillInTheBlankMultipleChoiceQuestionStudiableMetadata, C1457d cardEdge) {
        Intrinsics.checkNotNullParameter(fillInTheBlankMultipleChoiceQuestionStudiableMetadata, "fillInTheBlankMultipleChoiceQuestionStudiableMetadata");
        Intrinsics.checkNotNullParameter(cardEdge, "cardEdge");
        this.a = fillInTheBlankMultipleChoiceQuestionStudiableMetadata;
        this.b = cardEdge;
        StudiableMetadataType$Companion studiableMetadataType$Companion = assistantMode.enums.s.Companion;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a.equals(iVar.a) && this.b.equals(iVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "FillInTheBlankMultipleChoiceQuestionConfig(fillInTheBlankMultipleChoiceQuestionStudiableMetadata=" + this.a + ", cardEdge=" + this.b + ")";
    }
}
