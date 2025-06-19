package androidx.compose.foundation.relocation;

import androidx.compose.animation.core.C0242g;
import androidx.compose.ui.node.AbstractC0910f;
import androidx.compose.ui.node.InterfaceC0917m;
import androidx.compose.ui.node.a0;
import androidx.compose.ui.p;
import androidx.compose.ui.q;
import kotlin.Unit;

/* loaded from: classes.dex */
public abstract class d {
    public static final q a(q qVar, c cVar) {
        return qVar.g(new BringIntoViewRequesterElement(cVar));
    }

    public static final Object b(InterfaceC0917m interfaceC0917m, androidx.compose.ui.geometry.c cVar, kotlin.coroutines.jvm.internal.c cVar2) {
        a aVar;
        Object objS;
        if (!((p) interfaceC0917m).a.m) {
            return Unit.a;
        }
        a0 a0VarU = AbstractC0910f.u(interfaceC0917m);
        if (((p) interfaceC0917m).a.m) {
            a kVar = (a) AbstractC0910f.j(interfaceC0917m, j.p);
            if (kVar == null) {
                kVar = new k(interfaceC0917m);
            }
            aVar = kVar;
        } else {
            aVar = null;
        }
        return (aVar != null && (objS = aVar.S(a0VarU, new C0242g(4, cVar, a0VarU), cVar2)) == kotlin.coroutines.intrinsics.a.a) ? objS : Unit.a;
    }
}
