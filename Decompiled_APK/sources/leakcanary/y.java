package leakcanary;

import android.app.Application;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import java.util.ArrayList;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y {
    public static Pair a;
    public static boolean b;

    public static final void a(Application application) {
        if (b) {
            return;
        }
        try {
            if (a == null) {
                FrameLayout frameLayout = new FrameLayout(application);
                for (int i = 0; i < 32; i++) {
                    frameLayout.addView(new View(application));
                }
                a = new Pair(frameLayout, new ArrayList());
            }
            Pair pair = a;
            if (pair == null) {
                Intrinsics.l();
            }
            ((ViewGroup) pair.a).addChildrenForAccessibility((ArrayList) pair.b);
        } catch (Throwable unused) {
            b = true;
        }
    }
}
