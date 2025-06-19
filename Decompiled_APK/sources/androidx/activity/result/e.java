package androidx.activity.result;

import androidx.lifecycle.C;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e {
    public final C a;
    public final ArrayList b;

    public e(C lifecycle) {
        Intrinsics.checkNotNullParameter(lifecycle, "lifecycle");
        this.a = lifecycle;
        this.b = new ArrayList();
    }
}
