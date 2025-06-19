package assistantMode.tasks.progress;

import assistantMode.enums.k;
import assistantMode.refactored.types.Task;
import java.util.LinkedHashSet;
import java.util.Set;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final Set a;
    public final Task b;
    public final k c;
    public final LinkedHashSet d;
    public final LinkedHashSet e;
    public final LinkedHashSet f;

    public a(Set studiableItemIds, Task task, k questionType) {
        Intrinsics.checkNotNullParameter(studiableItemIds, "studiableItemIds");
        Intrinsics.checkNotNullParameter(task, "task");
        Intrinsics.checkNotNullParameter(questionType, "questionType");
        this.a = studiableItemIds;
        this.b = task;
        this.c = questionType;
        this.d = new LinkedHashSet();
        this.e = new LinkedHashSet();
        this.f = CollectionsKt.z0(studiableItemIds);
    }
}
