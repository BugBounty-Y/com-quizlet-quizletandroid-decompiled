package androidx.work.impl.model;

import androidx.work.C1437k;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m {
    public final String a;
    public final C1437k b;

    public m(String workSpecId, C1437k progress) {
        Intrinsics.checkNotNullParameter(workSpecId, "workSpecId");
        Intrinsics.checkNotNullParameter(progress, "progress");
        this.a = workSpecId;
        this.b = progress;
    }
}
