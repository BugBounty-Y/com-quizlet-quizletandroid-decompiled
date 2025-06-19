package assistantMode.types.gradingContext;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes.dex */
public final class UserMatchQuestionPair implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final Long b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return UserMatchQuestionPair$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ UserMatchQuestionPair(int i, long j, Long l) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, UserMatchQuestionPair$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = l;
    }

    @Override // assistantMode.types.gradingContext.a
    public final long a() {
        return this.a;
    }

    @Override // assistantMode.types.gradingContext.a
    public final Long b() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UserMatchQuestionPair)) {
            return false;
        }
        UserMatchQuestionPair userMatchQuestionPair = (UserMatchQuestionPair) obj;
        return this.a == userMatchQuestionPair.a && Intrinsics.b(this.b, userMatchQuestionPair.b);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        Long l = this.b;
        return iHashCode + (l == null ? 0 : l.hashCode());
    }

    public final String toString() {
        return "UserMatchQuestionPair(promptIndex=" + this.a + ", optionIndex=" + this.b + ")";
    }

    public UserMatchQuestionPair(int i, Integer num) {
        long j = i;
        Long lValueOf = num != null ? Long.valueOf(num.intValue()) : null;
        this.a = j;
        this.b = lValueOf;
    }
}
