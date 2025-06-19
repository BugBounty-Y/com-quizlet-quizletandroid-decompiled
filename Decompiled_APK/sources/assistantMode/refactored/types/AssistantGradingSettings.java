package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class AssistantGradingSettings {

    @NotNull
    public static final Companion Companion = new Companion();
    public final boolean a;
    public final boolean b;
    public final boolean c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return AssistantGradingSettings$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ AssistantGradingSettings(int i, boolean z, boolean z2, boolean z3) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, AssistantGradingSettings$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = z;
        this.b = z2;
        this.c = z3;
    }

    public final grading.core.d a() {
        return new grading.core.d(this.a, this.b, this.c, false);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AssistantGradingSettings)) {
            return false;
        }
        AssistantGradingSettings assistantGradingSettings = (AssistantGradingSettings) obj;
        return this.a == assistantGradingSettings.a && this.b == assistantGradingSettings.b && this.c == assistantGradingSettings.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(Boolean.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AssistantGradingSettings(acceptsPartialAnswer=");
        sb.append(this.a);
        sb.append(", acceptsAnswersWithTypos=");
        sb.append(this.b);
        sb.append(", acceptsSmartGrading=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }

    public AssistantGradingSettings(boolean z, boolean z2) {
        this.a = z;
        this.b = false;
        this.c = z2;
    }
}
