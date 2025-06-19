package androidx.compose.foundation.selection;

import androidx.compose.animation.d0;
import androidx.compose.foundation.AbstractC0455m0;
import androidx.compose.foundation.InterfaceC0369j0;
import androidx.compose.foundation.InterfaceC0461p0;
import androidx.compose.foundation.gestures.T;
import androidx.compose.foundation.interaction.k;
import androidx.compose.foundation.interaction.l;
import androidx.compose.material3.A4;
import androidx.compose.material3.D4;
import androidx.compose.material3.K4;
import androidx.compose.material3.internal.Y;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.draw.g;
import androidx.compose.ui.n;
import androidx.compose.ui.q;
import androidx.compose.ui.semantics.h;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3119d0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class b extends r implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(k kVar, boolean z, boolean z2, A4 a4) {
        super(3);
        D4 d4 = D4.a;
        D4 d42 = D4.a;
        this.d = kVar;
        this.b = z;
        this.c = z2;
        this.e = a4;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        l lVar;
        Object obj4 = this.e;
        Object obj5 = this.d;
        switch (this.a) {
            case 0:
                ((Number) obj3).intValue();
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                c0814p.X(-2124609672);
                InterfaceC0369j0 interfaceC0369j0 = (InterfaceC0369j0) c0814p.j(AbstractC0455m0.a);
                if (interfaceC0369j0 instanceof InterfaceC0461p0) {
                    c0814p.X(-1412264498);
                    c0814p.p(false);
                    lVar = null;
                } else {
                    c0814p.X(-1412156525);
                    Object objI = c0814p.I();
                    if (objI == C0804k.a) {
                        objI = d0.i(c0814p);
                    }
                    lVar = (l) objI;
                    c0814p.p(false);
                }
                l lVar2 = lVar;
                q qVarA = d.a(n.b, this.b, lVar2, interfaceC0369j0, this.c, (h) obj5, (Function0) obj4);
                c0814p.p(false);
                return qVarA;
            default:
                ((Number) obj3).intValue();
                C0814p c0814p2 = (C0814p) ((InterfaceC0806l) obj2);
                c0814p2.X(-891038934);
                float f = D4.e;
                float f2 = D4.d;
                InterfaceC0773a0 interfaceC0773a0D = Y.d(this.b, this.c, ((Boolean) AbstractC3119d0.h((k) obj5, c0814p2, 0).getValue()).booleanValue(), (A4) obj4, f, f2, c0814p2, 0);
                n nVar = n.b;
                float f3 = K4.a;
                q qVarG = g.g(nVar, new T(interfaceC0773a0D, 8));
                c0814p2.p(false);
                return qVarG;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(boolean z, boolean z2, h hVar, Function0 function0) {
        super(3);
        this.b = z;
        this.c = z2;
        this.d = hVar;
        this.e = function0;
    }
}
