package assistantMode.refactored.types;

import androidx.compose.animation.d0;
import assistantMode.enums.j;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.F;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes.dex */
public final class TaskWithProgress {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] d = {new F(j.f, TaskQuestionTypeProgress$$serializer.INSTANCE, 1), null, null};
    public final Map a;
    public final Task b;
    public final TaskProgress c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return TaskWithProgress$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ TaskWithProgress(int i, Map map, Task task, TaskProgress taskProgress) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, TaskWithProgress$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = map;
        this.b = task;
        this.c = taskProgress;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof TaskWithProgress)) {
            return false;
        }
        TaskWithProgress taskWithProgress = (TaskWithProgress) obj;
        return Intrinsics.b(this.a, taskWithProgress.a) && Intrinsics.b(this.b, taskWithProgress.b) && Intrinsics.b(this.c, taskWithProgress.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b.a);
    }

    public final String toString() {
        return "TaskWithProgress(progressByQuestionType=" + this.a + ", task=" + this.b + ", totalProgress=" + this.c + ")";
    }

    public TaskWithProgress(Task task, assistantMode.tasks.progress.b taskProgressTracker) {
        Intrinsics.checkNotNullParameter(task, "task");
        Intrinsics.checkNotNullParameter(taskProgressTracker, "taskProgressTracker");
        LinkedHashMap linkedHashMapC = taskProgressTracker.c();
        TaskProgress taskProgressB = taskProgressTracker.b();
        this.a = linkedHashMapC;
        this.b = task;
        this.c = taskProgressB;
    }
}
