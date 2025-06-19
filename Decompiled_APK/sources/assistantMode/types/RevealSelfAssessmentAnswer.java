package assistantMode.types;

import assistantMode.enums.EnumC1448b;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class RevealSelfAssessmentAnswer extends v {

    @NotNull
    public static final Companion Companion = new Companion();
    public final EnumC1448b a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RevealSelfAssessmentAnswer$$serializer.INSTANCE;
        }
    }

    public RevealSelfAssessmentAnswer(int i, EnumC1448b enumC1448b) {
        if (1 == (i & 1)) {
            this.a = enumC1448b;
        } else {
            AbstractC5047c0.k(i, 1, RevealSelfAssessmentAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof RevealSelfAssessmentAnswer) && this.a == ((RevealSelfAssessmentAnswer) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "RevealSelfAssessmentAnswer(value=" + this.a + ")";
    }

    public RevealSelfAssessmentAnswer(EnumC1448b value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.a = value;
    }
}
