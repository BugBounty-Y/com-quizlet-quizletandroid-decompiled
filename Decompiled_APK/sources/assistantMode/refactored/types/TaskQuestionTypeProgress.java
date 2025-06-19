package assistantMode.refactored.types;

import kotlin.Metadata;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class TaskQuestionTypeProgress {

    @NotNull
    public static final Companion Companion = new Companion();
    public final int a;
    public final int b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TaskQuestionTypeProgress$$serializer.INSTANCE;
        }
    }

    public TaskQuestionTypeProgress(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TaskQuestionTypeProgress)) {
            return false;
        }
        TaskQuestionTypeProgress taskQuestionTypeProgress = (TaskQuestionTypeProgress) obj;
        return this.a == taskQuestionTypeProgress.a && this.b == taskQuestionTypeProgress.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("TaskQuestionTypeProgress(numItemsCompleted=");
        sb.append(this.a);
        sb.append(", numTotalItems=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }

    public /* synthetic */ TaskQuestionTypeProgress(int i, int i2, int i3) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, TaskQuestionTypeProgress$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = i2;
        this.b = i3;
    }
}
