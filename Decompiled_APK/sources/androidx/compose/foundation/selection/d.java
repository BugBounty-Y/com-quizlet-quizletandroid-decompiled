package androidx.compose.foundation.selection;

import androidx.compose.foundation.AbstractC0455m0;
import androidx.compose.foundation.InterfaceC0369j0;
import androidx.compose.foundation.InterfaceC0461p0;
import androidx.compose.foundation.interaction.l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import androidx.compose.ui.semantics.h;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public abstract class d {
    public static final q a(q qVar, boolean z, l lVar, InterfaceC0369j0 interfaceC0369j0, boolean z2, h hVar, Function0 function0) {
        q qVarG;
        if (interfaceC0369j0 instanceof InterfaceC0461p0) {
            qVarG = new SelectableElement(z, lVar, (InterfaceC0461p0) interfaceC0369j0, z2, hVar, function0);
        } else if (interfaceC0369j0 == null) {
            qVarG = new SelectableElement(z, lVar, null, z2, hVar, function0);
        } else {
            n nVar = n.b;
            qVarG = lVar != null ? AbstractC0455m0.a(nVar, lVar, interfaceC0369j0).g(new SelectableElement(z, lVar, null, z2, hVar, function0)) : androidx.compose.ui.a.a(nVar, new c(interfaceC0369j0, z, z2, hVar, function0, 0));
        }
        return qVar.g(qVarG);
    }

    public static final q b(q qVar, boolean z, l lVar, InterfaceC0369j0 interfaceC0369j0, boolean z2, h hVar, Function1 function1) {
        q qVarG;
        if (interfaceC0369j0 instanceof InterfaceC0461p0) {
            qVarG = new ToggleableElement(z, lVar, (InterfaceC0461p0) interfaceC0369j0, z2, hVar, function1);
        } else if (interfaceC0369j0 == null) {
            qVarG = new ToggleableElement(z, lVar, null, z2, hVar, function1);
        } else {
            n nVar = n.b;
            qVarG = lVar != null ? AbstractC0455m0.a(nVar, lVar, interfaceC0369j0).g(new ToggleableElement(z, lVar, null, z2, hVar, function1)) : androidx.compose.ui.a.a(nVar, new c(interfaceC0369j0, z, z2, hVar, function1, 1));
        }
        return qVar.g(qVarG);
    }
}
