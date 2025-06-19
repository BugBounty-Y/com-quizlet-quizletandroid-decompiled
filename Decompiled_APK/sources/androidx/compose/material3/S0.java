package androidx.compose.material3;

import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class S0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ androidx.compose.foundation.lazy.grid.A a;
    public final /* synthetic */ int b;
    public final /* synthetic */ kotlinx.coroutines.C c;
    public final /* synthetic */ String d;
    public final /* synthetic */ String e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S0(androidx.compose.foundation.lazy.grid.A a, int i, kotlinx.coroutines.C c, String str, String str2) {
        super(1);
        this.a = a;
        this.b = i;
        this.c = c;
        this.d = str;
        this.e = str2;
    }

    /* JADX WARN: Type inference failed for: r1v8, types: [java.lang.Object, java.util.List] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Object objJ;
        androidx.compose.foundation.lazy.grid.r rVar;
        androidx.compose.ui.semantics.v vVar = (androidx.compose.ui.semantics.v) obj;
        androidx.compose.foundation.lazy.grid.A a = this.a;
        int iA = a.b.a();
        int i = this.b;
        if (iA == i || ((rVar = (androidx.compose.foundation.lazy.grid.r) CollectionsKt.V(a.g().g)) != null && rVar.a == i)) {
            float f = Z0.a;
            kotlinx.coroutines.C c = this.c;
            objJ = kotlin.collections.B.j(new androidx.compose.ui.semantics.d(this.d, new X0(a, c, 1)), new androidx.compose.ui.semantics.d(this.e, new X0(a, c, 0)));
        } else {
            objJ = kotlin.collections.K.a;
        }
        kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
        androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.j.v;
        kotlin.reflect.n nVar = androidx.compose.ui.semantics.t.a[25];
        uVar.a(vVar, objJ);
        return Unit.a;
    }
}
