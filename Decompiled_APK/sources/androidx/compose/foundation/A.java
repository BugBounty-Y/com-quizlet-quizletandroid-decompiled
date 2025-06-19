package androidx.compose.foundation;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class A extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public final /* synthetic */ InterfaceC0369j0 a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ String c;
    public final /* synthetic */ androidx.compose.ui.semantics.h d;
    public final /* synthetic */ Function0 e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(InterfaceC0369j0 interfaceC0369j0, boolean z, String str, androidx.compose.ui.semantics.h hVar, Function0 function0) {
        super(3);
        this.a = interfaceC0369j0;
        this.b = z;
        this.c = str;
        this.d = hVar;
        this.e = function0;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        ((Number) obj3).intValue();
        C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
        c0814p.X(-1525724089);
        Object objI = c0814p.I();
        if (objI == C0804k.a) {
            objI = androidx.compose.animation.d0.i(c0814p);
        }
        androidx.compose.foundation.interaction.l lVar = (androidx.compose.foundation.interaction.l) objI;
        androidx.compose.ui.q qVarG = AbstractC0455m0.a(androidx.compose.ui.n.b, lVar, this.a).g(new ClickableElement(lVar, null, this.b, this.c, this.d, this.e));
        c0814p.p(false);
        return qVarG;
    }
}
