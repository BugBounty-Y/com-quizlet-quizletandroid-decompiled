package androidx.compose.animation;

import android.view.ViewConfiguration;
import androidx.compose.animation.core.C0276z;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.AbstractC0955m0;

/* loaded from: classes.dex */
public abstract class p0 {
    public static final float a = ViewConfiguration.getScrollFriction();

    public static final C0276z a(InterfaceC0806l interfaceC0806l) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        androidx.compose.ui.unit.b bVar = (androidx.compose.ui.unit.b) c0814p.j(AbstractC0955m0.f);
        boolean zC = c0814p.c(bVar.a());
        Object objI = c0814p.I();
        if (zC || objI == C0804k.a) {
            objI = new C0276z(new androidx.appcompat.app.Q(bVar));
            c0814p.i0(objI);
        }
        return (C0276z) objI;
    }
}
