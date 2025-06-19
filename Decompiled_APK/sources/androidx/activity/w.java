package androidx.activity;

import android.os.Build;
import android.view.View;
import android.view.Window;
import androidx.core.view.E0;
import androidx.core.view.F0;
import androidx.core.view.G0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3275u6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public class w {
    public void a(Window window) {
        Intrinsics.checkNotNullParameter(window, "window");
    }

    public void b(@NotNull P statusBarStyle, @NotNull P navigationBarStyle, @NotNull Window window, @NotNull View view, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(statusBarStyle, "statusBarStyle");
        Intrinsics.checkNotNullParameter(navigationBarStyle, "navigationBarStyle");
        Intrinsics.checkNotNullParameter(window, "window");
        Intrinsics.checkNotNullParameter(view, "view");
        AbstractC3275u6.b(window, false);
        window.setStatusBarColor(z ? statusBarStyle.b : statusBarStyle.a);
        window.setNavigationBarColor(z2 ? navigationBarStyle.b : navigationBarStyle.a);
        com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(view);
        int i = Build.VERSION.SDK_INT;
        AbstractC3291w6 g0 = i >= 35 ? new G0(window, aVar) : i >= 30 ? new F0(window, aVar) : new E0(window, aVar);
        g0.d(!z);
        g0.c(!z2);
    }
}
