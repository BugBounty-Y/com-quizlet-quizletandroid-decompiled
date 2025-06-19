package androidx.activity;

import android.content.res.Resources;
import android.graphics.Color;
import android.os.Build;
import android.view.View;
import android.view.Window;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class v {
    public static final int a = Color.argb(230, 255, 255, 255);
    public static final int b = Color.argb(128, 27, 27, 27);

    public static final void a(s sVar) {
        Intrinsics.checkNotNullParameter(sVar, "<this>");
        b(sVar, null, 3);
    }

    public static void b(s sVar, P p, int i) {
        int i2 = i & 1;
        O detectDarkMode = O.b;
        if (i2 != 0) {
            Intrinsics.checkNotNullParameter(detectDarkMode, "detectDarkMode");
            p = new P(0, 0, 0, detectDarkMode);
        }
        P statusBarStyle = p;
        Intrinsics.checkNotNullParameter(detectDarkMode, "detectDarkMode");
        P navigationBarStyle = new P(a, b, 0, detectDarkMode);
        Intrinsics.checkNotNullParameter(sVar, "<this>");
        Intrinsics.checkNotNullParameter(statusBarStyle, "statusBarStyle");
        Intrinsics.checkNotNullParameter(navigationBarStyle, "navigationBarStyle");
        View decorView = sVar.getWindow().getDecorView();
        Intrinsics.checkNotNullExpressionValue(decorView, "window.decorView");
        Function1 function1 = statusBarStyle.d;
        Resources resources = decorView.getResources();
        Intrinsics.checkNotNullExpressionValue(resources, "view.resources");
        boolean zBooleanValue = ((Boolean) function1.invoke(resources)).booleanValue();
        Resources resources2 = decorView.getResources();
        Intrinsics.checkNotNullExpressionValue(resources2, "view.resources");
        boolean zBooleanValue2 = ((Boolean) detectDarkMode.invoke(resources2)).booleanValue();
        int i3 = Build.VERSION.SDK_INT;
        w b2 = i3 >= 30 ? new B() : i3 >= 29 ? new A() : i3 >= 28 ? new y() : new w();
        Window window = sVar.getWindow();
        Intrinsics.checkNotNullExpressionValue(window, "window");
        b2.b(statusBarStyle, navigationBarStyle, window, decorView, zBooleanValue, zBooleanValue2);
        Window window2 = sVar.getWindow();
        Intrinsics.checkNotNullExpressionValue(window2, "window");
        b2.a(window2);
    }
}
