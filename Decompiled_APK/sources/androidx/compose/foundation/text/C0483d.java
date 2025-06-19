package androidx.compose.foundation.text;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.text.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0483d extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public static final C0483d a = new C0483d(3);

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        androidx.compose.ui.q qVar = (androidx.compose.ui.q) obj;
        ((Number) obj3).intValue();
        C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
        c0814p.X(-2126899193);
        long j = ((androidx.compose.foundation.text.selection.p0) c0814p.j(androidx.compose.foundation.text.selection.q0.a)).a;
        androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
        boolean zE = c0814p.e(j);
        Object objI = c0814p.I();
        if (zE || objI == C0804k.a) {
            objI = new C0481c(0, j);
            c0814p.i0(objI);
        }
        androidx.compose.ui.q qVarG = qVar.g(androidx.compose.ui.draw.g.f(nVar, (Function1) objI));
        c0814p.p(false);
        return qVarG;
    }
}
