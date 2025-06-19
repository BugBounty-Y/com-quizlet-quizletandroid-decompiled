package androidx.activity.compose;

import android.app.Activity;
import android.content.Context;
import android.content.ContextWrapper;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.X0;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class k extends kotlin.jvm.internal.r implements Function1 {
    public static final k a = new k(1);

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        InterfaceC0803j0 interfaceC0803j0 = (InterfaceC0803j0) obj;
        X0 x0 = AndroidCompositionLocals_androidKt.b;
        interfaceC0803j0.getClass();
        Context baseContext = (Context) C0776c.B(interfaceC0803j0, x0);
        while (true) {
            if (!(baseContext instanceof ContextWrapper)) {
                baseContext = null;
                break;
            }
            if (baseContext instanceof Activity) {
                break;
            }
            baseContext = ((ContextWrapper) baseContext).getBaseContext();
        }
        return (Activity) baseContext;
    }
}
