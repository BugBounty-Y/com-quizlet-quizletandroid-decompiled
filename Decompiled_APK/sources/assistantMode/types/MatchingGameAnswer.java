package assistantMode.types;

import assistantMode.grading.MatchingGameAnswerPair;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class MatchingGameAnswer extends v {

    @NotNull
    public static final Companion Companion = new Companion();
    public final MatchingGameAnswerPair a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MatchingGameAnswer$$serializer.INSTANCE;
        }
    }

    public MatchingGameAnswer(int i, MatchingGameAnswerPair matchingGameAnswerPair) {
        if (1 == (i & 1)) {
            this.a = matchingGameAnswerPair;
        } else {
            AbstractC5047c0.k(i, 1, MatchingGameAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof MatchingGameAnswer) && Intrinsics.b(this.a, ((MatchingGameAnswer) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "MatchingGameAnswer(value=" + this.a + ")";
    }

    public MatchingGameAnswer(MatchingGameAnswerPair value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.a = value;
    }
}
