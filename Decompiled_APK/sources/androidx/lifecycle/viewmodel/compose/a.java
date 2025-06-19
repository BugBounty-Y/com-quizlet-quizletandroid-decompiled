package androidx.lifecycle.viewmodel.compose;

import android.view.View;
import androidx.compose.runtime.B;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AndroidCompositionLocals_androidKt;
import androidx.lifecycle.C0;
import androidx.lifecycle.compose.f;
import androidx.lifecycle.p0;

/* loaded from: classes.dex */
public abstract class a {
    public static final B a = new B(new f(1));

    public static C0 a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        C0 c0 = (C0) c0814p.j(a);
        if (c0 != null) {
            c0814p.X(1260196493);
            c0814p.p(false);
            return c0;
        }
        c0814p.X(1260197609);
        C0 c0G = p0.g((View) c0814p.j(AndroidCompositionLocals_androidKt.f));
        c0814p.p(false);
        return c0G;
    }
}
