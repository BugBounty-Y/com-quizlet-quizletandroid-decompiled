package assistantMode.refactored.types;

import assistantMode.enums.l;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class AnswerSidePriorities {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] c = {new C5048d(l.f, 0), null};
    public final List a;
    public final boolean b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return AnswerSidePriorities$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ AnswerSidePriorities(boolean z, int i, List list) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, AnswerSidePriorities$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = list;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AnswerSidePriorities)) {
            return false;
        }
        AnswerSidePriorities answerSidePriorities = (AnswerSidePriorities) obj;
        return Intrinsics.b(this.a, answerSidePriorities.a) && this.b == answerSidePriorities.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "AnswerSidePriorities(answerSidePriorities=" + this.a + ", allowKmpLanguageLearningLogicOverwrite=" + this.b + ")";
    }
}
