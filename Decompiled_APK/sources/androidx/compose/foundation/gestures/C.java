package androidx.compose.foundation.gestures;

import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class C extends kotlin.jvm.internal.r implements kotlin.jvm.functions.c {
    public final /* synthetic */ int a;
    public final /* synthetic */ Function1 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C(int i, Function1 function1) {
        super(3);
        this.a = i;
        this.b = function1;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.a) {
            case 0:
                long j = ((androidx.compose.ui.geometry.b) obj3).a;
                this.b.invoke(new androidx.compose.ui.geometry.b(((androidx.compose.ui.input.pointer.n) obj2).c));
                return Unit.a;
            default:
                ((Number) obj3).intValue();
                C0814p c0814p = (C0814p) ((InterfaceC0806l) obj2);
                c0814p.X(-1608161351);
                Function1 function1 = this.b;
                boolean zF = c0814p.f(function1);
                Object objI = c0814p.I();
                if (zF || objI == C0804k.a) {
                    objI = new androidx.compose.foundation.layout.E(function1);
                    c0814p.i0(objI);
                }
                androidx.compose.foundation.layout.E e = (androidx.compose.foundation.layout.E) objI;
                c0814p.p(false);
                return e;
        }
    }
}
