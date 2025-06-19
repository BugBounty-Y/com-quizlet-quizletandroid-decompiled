package androidx.compose.foundation.relocation;

import android.graphics.Rect;
import android.view.View;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0917m;
import androidx.compose.ui.node.a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class k implements a {
    public final /* synthetic */ InterfaceC0917m a;

    public k(InterfaceC0917m interfaceC0917m) {
        this.a = interfaceC0917m;
    }

    @Override // androidx.compose.foundation.relocation.a
    public final Object S(a0 a0Var, Function0 function0, kotlin.coroutines.jvm.internal.c cVar) {
        View viewX = AbstractC0910f.x(this.a);
        long jU = a0Var.U(0L);
        androidx.compose.ui.geometry.c cVar2 = (androidx.compose.ui.geometry.c) function0.invoke();
        androidx.compose.ui.geometry.c cVarJ = cVar2 != null ? cVar2.j(jU) : null;
        if (cVarJ != null) {
            viewX.requestRectangleOnScreen(new Rect((int) cVarJ.a, (int) cVarJ.b, (int) cVarJ.c, (int) cVarJ.d), false);
        }
        return Unit.a;
    }
}
