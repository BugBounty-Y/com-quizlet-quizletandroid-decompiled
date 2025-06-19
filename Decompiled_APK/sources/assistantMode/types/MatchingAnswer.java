package assistantMode.types;

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
public final class MatchingAnswer extends v {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] b = {new kotlinx.serialization.c(K.a(assistantMode.types.gradingContext.a.class), new Annotation[0])};
    public final assistantMode.types.gradingContext.a a;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return MatchingAnswer$$serializer.INSTANCE;
        }
    }

    public MatchingAnswer(int i, assistantMode.types.gradingContext.a aVar) {
        if (1 == (i & 1)) {
            this.a = aVar;
        } else {
            AbstractC5047c0.k(i, 1, MatchingAnswer$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof MatchingAnswer) && Intrinsics.b(this.a, ((MatchingAnswer) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "MatchingAnswer(value=" + this.a + ")";
    }

    public MatchingAnswer(assistantMode.types.gradingContext.a value) {
        Intrinsics.checkNotNullParameter(value, "value");
        this.a = value;
    }
}
