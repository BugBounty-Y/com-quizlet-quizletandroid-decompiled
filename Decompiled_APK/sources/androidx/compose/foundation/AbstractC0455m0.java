package androidx.compose.foundation;

import androidx.compose.runtime.X0;

/* renamed from: androidx.compose.foundation.m0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0455m0 {
    public static final X0 a = new X0(C0373l0.b);

    public static final androidx.compose.ui.q a(androidx.compose.ui.q qVar, androidx.compose.foundation.interaction.k kVar, InterfaceC0369j0 interfaceC0369j0) {
        return interfaceC0369j0 == null ? qVar : interfaceC0369j0 instanceof InterfaceC0461p0 ? qVar.g(new IndicationModifierElement(kVar, (InterfaceC0461p0) interfaceC0369j0)) : androidx.compose.ui.a.a(qVar, new androidx.compose.animation.D(1, interfaceC0369j0, kVar));
    }
}
