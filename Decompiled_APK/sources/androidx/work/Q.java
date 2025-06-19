package androidx.work;

import java.util.Set;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class Q {
    public final UUID a;
    public final androidx.work.impl.model.q b;
    public final Set c;

    public Q(UUID id, androidx.work.impl.model.q workSpec, Set tags) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(workSpec, "workSpec");
        Intrinsics.checkNotNullParameter(tags, "tags");
        this.a = id;
        this.b = workSpec;
        this.c = tags;
    }
}
