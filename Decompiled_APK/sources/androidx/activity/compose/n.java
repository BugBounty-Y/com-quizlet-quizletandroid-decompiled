package androidx.activity.compose;

import android.content.Context;
import android.content.ContextWrapper;
import android.view.View;
import androidx.activity.N;
import androidx.compose.runtime.B;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3315z6;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class n {
    public static final B a = new B(e.d);

    public static N a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        N n = (N) c0814p.j(a);
        Object obj = null;
        if (n == null) {
            c0814p.X(544166745);
            View view = (View) c0814p.j(AndroidCompositionLocals_androidKt.f);
            Intrinsics.checkNotNullParameter(view, "<this>");
            while (true) {
                if (view == null) {
                    n = null;
                    break;
                }
                Object tag = view.getTag(R.id.view_tree_on_back_pressed_dispatcher_owner);
                N n2 = tag instanceof N ? (N) tag : null;
                if (n2 != null) {
                    n = n2;
                    break;
                }
                Object objB = AbstractC3315z6.b(view);
                view = objB instanceof View ? (View) objB : null;
            }
            c0814p.p(false);
        } else {
            c0814p.X(544164296);
            c0814p.p(false);
        }
        if (n != null) {
            c0814p.X(544164377);
            c0814p.p(false);
            return n;
        }
        c0814p.X(544168748);
        Context baseContext = (Context) c0814p.j(AndroidCompositionLocals_androidKt.b);
        while (true) {
            if (!(baseContext instanceof ContextWrapper)) {
                break;
            }
            if (baseContext instanceof N) {
                obj = baseContext;
                break;
            }
            baseContext = ((ContextWrapper) baseContext).getBaseContext();
        }
        N n3 = (N) obj;
        c0814p.p(false);
        return n3;
    }
}
