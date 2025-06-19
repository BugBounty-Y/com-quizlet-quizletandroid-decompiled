package assistantMode.types;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class AssistantGradingSettingsSuggestion {

    @NotNull
    public static final Companion Companion = new Companion();
    public final Boolean a;
    public final Boolean b;
    public final Boolean c;
    public final Boolean d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return AssistantGradingSettingsSuggestion$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ AssistantGradingSettingsSuggestion(int i, Boolean bool, Boolean bool2, Boolean bool3, Boolean bool4) {
        if ((i & 1) == 0) {
            this.a = null;
        } else {
            this.a = bool;
        }
        if ((i & 2) == 0) {
            this.b = null;
        } else {
            this.b = bool2;
        }
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = bool3;
        }
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = bool4;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AssistantGradingSettingsSuggestion)) {
            return false;
        }
        AssistantGradingSettingsSuggestion assistantGradingSettingsSuggestion = (AssistantGradingSettingsSuggestion) obj;
        return Intrinsics.b(this.a, assistantGradingSettingsSuggestion.a) && Intrinsics.b(this.b, assistantGradingSettingsSuggestion.b) && Intrinsics.b(this.c, assistantGradingSettingsSuggestion.c) && Intrinsics.b(this.d, assistantGradingSettingsSuggestion.d);
    }

    public final int hashCode() {
        Boolean bool = this.a;
        int iHashCode = (bool == null ? 0 : bool.hashCode()) * 31;
        Boolean bool2 = this.b;
        int iHashCode2 = (iHashCode + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        Boolean bool3 = this.c;
        int iHashCode3 = (iHashCode2 + (bool3 == null ? 0 : bool3.hashCode())) * 31;
        Boolean bool4 = this.d;
        return iHashCode3 + (bool4 != null ? bool4.hashCode() : 0);
    }

    public final String toString() {
        return "AssistantGradingSettingsSuggestion(acceptsPartialAnswer=" + this.a + ", acceptsAnswersWithTypos=" + this.b + ", acceptsSmartGrading=" + this.c + ", allowsRetry=" + this.d + ")";
    }

    public AssistantGradingSettingsSuggestion(Boolean bool, Boolean bool2, Boolean bool3, Boolean bool4, int i) {
        bool = (i & 1) != 0 ? null : bool;
        bool2 = (i & 2) != 0 ? null : bool2;
        bool3 = (i & 4) != 0 ? null : bool3;
        bool4 = (i & 8) != 0 ? null : bool4;
        this.a = bool;
        this.b = bool2;
        this.c = bool3;
        this.d = bool4;
    }
}
