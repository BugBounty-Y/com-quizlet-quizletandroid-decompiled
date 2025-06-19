package assistantMode.types.gradingContext;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class ExpectedMatchQuestionPair implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final long b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ExpectedMatchQuestionPair$$serializer.INSTANCE;
        }
    }

    public ExpectedMatchQuestionPair(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    @Override // assistantMode.types.gradingContext.a
    public final long a() {
        return this.a;
    }

    @Override // assistantMode.types.gradingContext.a
    public final Long b() {
        return Long.valueOf(this.b);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ExpectedMatchQuestionPair)) {
            return false;
        }
        ExpectedMatchQuestionPair expectedMatchQuestionPair = (ExpectedMatchQuestionPair) obj;
        return this.a == expectedMatchQuestionPair.a && this.b == expectedMatchQuestionPair.b;
    }

    public final int hashCode() {
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExpectedMatchQuestionPair(promptIndex=");
        sb.append(this.a);
        sb.append(", optionIndex=");
        return android.support.v4.media.session.a.g(this.b, ")", sb);
    }

    public /* synthetic */ ExpectedMatchQuestionPair(long j, long j2, int i) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, ExpectedMatchQuestionPair$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = j2;
    }
}
