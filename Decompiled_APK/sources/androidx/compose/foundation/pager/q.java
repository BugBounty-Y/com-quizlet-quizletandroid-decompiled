package androidx.compose.foundation.pager;

import androidx.compose.material3.F3;
import androidx.compose.material3.G3;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class q extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ q(boolean z, Object obj, Object obj2, int i) {
        super(1);
        this.a = i;
        this.b = z;
        this.c = obj;
        this.d = obj2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        boolean z = this.b;
        Object obj2 = this.d;
        Object obj3 = this.c;
        switch (this.a) {
            case 0:
                androidx.compose.ui.semantics.v vVar = (androidx.compose.ui.semantics.v) obj;
                kotlinx.coroutines.C c = (kotlinx.coroutines.C) obj2;
                C0466e c0466e = (C0466e) obj3;
                if (z) {
                    p pVar = new p(c0466e, c, 0);
                    kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
                    androidx.compose.ui.semantics.k kVar = (androidx.compose.ui.semantics.k) vVar;
                    kVar.b(androidx.compose.ui.semantics.j.w, new androidx.compose.ui.semantics.a(null, pVar));
                    kVar.b(androidx.compose.ui.semantics.j.y, new androidx.compose.ui.semantics.a(null, new p(c0466e, c, 1)));
                } else {
                    p pVar2 = new p(c0466e, c, 2);
                    kotlin.reflect.n[] nVarArr2 = androidx.compose.ui.semantics.t.a;
                    androidx.compose.ui.semantics.k kVar2 = (androidx.compose.ui.semantics.k) vVar;
                    kVar2.b(androidx.compose.ui.semantics.j.x, new androidx.compose.ui.semantics.a(null, pVar2));
                    kVar2.b(androidx.compose.ui.semantics.j.z, new androidx.compose.ui.semantics.a(null, new p(c0466e, c, 3)));
                }
                return Unit.a;
            default:
                return new F3(z, (androidx.compose.ui.unit.b) obj3, (G3) obj, (Function1) obj2);
        }
    }
}
