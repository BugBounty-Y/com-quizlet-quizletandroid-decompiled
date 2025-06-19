package androidx.compose.foundation.selection;

import androidx.compose.animation.d0;
import androidx.compose.foundation.AbstractC0455m0;
import androidx.compose.foundation.InterfaceC0369j0;
import androidx.compose.foundation.interaction.l;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import androidx.compose.ui.semantics.h;
import kotlin.InterfaceC4938g;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class c extends r implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC0369j0 b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ h e;
    public final /* synthetic */ InterfaceC4938g f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c(InterfaceC0369j0 interfaceC0369j0, boolean z, boolean z2, h hVar, InterfaceC4938g interfaceC4938g, int i) {
        super(3);
        this.a = i;
        this.b = interfaceC0369j0;
        this.c = z;
        this.d = z2;
        this.e = hVar;
        this.f = interfaceC4938g;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                ((Number) obj3).intValue();
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                c0814p.X(-1525724089);
                Object objI = c0814p.I();
                if (objI == C0804k.a) {
                    objI = d0.i(c0814p);
                }
                l lVar = (l) objI;
                q qVarG = AbstractC0455m0.a(n.b, lVar, this.b).g(new SelectableElement(this.c, lVar, null, this.d, this.e, (Function0) this.f));
                c0814p.p(false);
                return qVarG;
            default:
                ((Number) obj3).intValue();
                C0814p c0814p2 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p2.X(-1525724089);
                Object objI2 = c0814p2.I();
                if (objI2 == C0804k.a) {
                    objI2 = d0.i(c0814p2);
                }
                l lVar2 = (l) objI2;
                q qVarG2 = AbstractC0455m0.a(n.b, lVar2, this.b).g(new ToggleableElement(this.c, lVar2, null, this.d, this.e, (Function1) this.f));
                c0814p2.p(false);
                return qVarG2;
        }
    }
}
