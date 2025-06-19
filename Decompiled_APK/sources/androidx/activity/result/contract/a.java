package androidx.activity.result.contract;

import android.content.Context;
import android.content.Intent;
import androidx.webkit.internal.p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class a {
    public abstract Intent a(Context context, Object obj);

    public p b(Context context, Object obj) {
        Intrinsics.checkNotNullParameter(context, "context");
        return null;
    }

    public abstract Object c(int i, Intent intent);
}
