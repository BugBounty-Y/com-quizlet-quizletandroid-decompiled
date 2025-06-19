package androidx.glance.appwidget.action;

import android.os.StrictMode;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class f {
    public static final f a = new f();

    @NotNull
    public final StrictMode.VmPolicy.Builder a(@NotNull StrictMode.VmPolicy.Builder builder) {
        return builder.permitUnsafeIntentLaunch();
    }
}
