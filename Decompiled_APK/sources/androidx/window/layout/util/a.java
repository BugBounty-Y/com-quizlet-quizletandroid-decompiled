package androidx.window.layout.util;

import android.content.Context;
import android.view.WindowInsets;
import android.view.WindowManager;
import androidx.core.view.D0;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class a {
    public static final a a = new a();

    @NotNull
    public final D0 a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        WindowInsets windowInsets = ((WindowManager) context.getSystemService(WindowManager.class)).getCurrentWindowMetrics().getWindowInsets();
        Intrinsics.checkNotNullExpressionValue(windowInsets, "context.getSystemService…indowMetrics.windowInsets");
        D0 d0H = D0.h(null, windowInsets);
        Intrinsics.checkNotNullExpressionValue(d0H, "toWindowInsetsCompat(platformInsets)");
        return d0H;
    }
}
