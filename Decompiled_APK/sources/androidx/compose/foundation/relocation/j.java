package androidx.compose.foundation.relocation;

import androidx.compose.foundation.C0473q;
import androidx.compose.foundation.gestures.C0333k;
import androidx.compose.ui.layout.r;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0925v;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.node.q0;
import androidx.compose.ui.p;
import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlinx.coroutines.E;

/* loaded from: classes.dex */
public final class j extends p implements a, InterfaceC0925v, q0 {
    public static final com.onetrust.otpublishers.headless.Internal.Helper.h p = new com.onetrust.otpublishers.headless.Internal.Helper.h(2);
    public C0333k n;
    public boolean o;

    public static final androidx.compose.ui.geometry.c M0(j jVar, a0 a0Var, Function0 function0) {
        androidx.compose.ui.geometry.c cVar;
        if (jVar.m && jVar.o) {
            a0 a0VarU = AbstractC0910f.u(jVar);
            if (!a0Var.W0().m) {
                a0Var = null;
            }
            if (a0Var != null && (cVar = (androidx.compose.ui.geometry.c) function0.invoke()) != null) {
                androidx.compose.ui.geometry.c cVarO = a0VarU.o(a0Var, false);
                return cVar.j(Q4.c(cVarO.a, cVarO.b));
            }
        }
        return null;
    }

    @Override // androidx.compose.ui.p
    public final boolean B0() {
        return false;
    }

    @Override // androidx.compose.foundation.relocation.a
    public final Object S(a0 a0Var, Function0 function0, kotlin.coroutines.jvm.internal.c cVar) {
        Object objM = E.m(new i(this, a0Var, function0, new C0473q(this, a0Var, function0), null), cVar);
        return objM == kotlin.coroutines.intrinsics.a.a ? objM : Unit.a;
    }

    @Override // androidx.compose.ui.node.q0
    public final Object m() {
        return p;
    }

    @Override // androidx.compose.ui.node.InterfaceC0925v
    public final void x(r rVar) {
        this.o = true;
    }
}
