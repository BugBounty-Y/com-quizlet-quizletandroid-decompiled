package androidx.core.content;

import android.content.Context;
import java.util.concurrent.Executor;

/* loaded from: classes.dex */
public abstract class a {
    public static Executor a(Context context) {
        return context.getMainExecutor();
    }
}
