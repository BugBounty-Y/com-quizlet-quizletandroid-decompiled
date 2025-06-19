package assistantMode.grading;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class LocalGradedAnswerMetadata implements b {

    @NotNull
    public static final Companion Companion = new Companion();
    public final boolean a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return LocalGradedAnswerMetadata$$serializer.INSTANCE;
        }
    }

    public LocalGradedAnswerMetadata() {
        this.a = false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof LocalGradedAnswerMetadata) && this.a == ((LocalGradedAnswerMetadata) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("LocalGradedAnswerMetadata(wasSmartGradingUsed="), this.a);
    }

    public LocalGradedAnswerMetadata(int i, boolean z) {
        if ((i & 1) == 0) {
            this.a = false;
        } else {
            this.a = z;
        }
        if (this.a) {
            throw new IllegalArgumentException("wasSmartGradingUsed should always be false in a locally graded answer");
        }
    }
}
