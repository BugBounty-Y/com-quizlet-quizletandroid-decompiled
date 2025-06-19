package androidx.compose.foundation;

import android.os.Build;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class t0 {
    public static final androidx.compose.ui.semantics.u a = new androidx.compose.ui.semantics.u("MagnifierPositionInRoot");

    public static boolean a() {
        return Build.VERSION.SDK_INT >= 28;
    }

    public static androidx.compose.ui.q b(Function1 function1, Function1 function12, E0 e0) {
        return a() ? new MagnifierElement(function1, function12, e0) : androidx.compose.ui.n.b;
    }
}
