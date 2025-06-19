package androidx.compose.material;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class W extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ Function0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ W(String str, Function0 function0, int i) {
        super(1);
        this.a = i;
        this.b = str;
        this.c = function0;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Function0 function0 = this.c;
        String str = this.b;
        switch (this.a) {
            case 0:
                androidx.compose.ui.semantics.v vVar = (androidx.compose.ui.semantics.v) obj;
                androidx.compose.ui.semantics.t.e(vVar, str);
                androidx.compose.ui.semantics.k kVar = (androidx.compose.ui.semantics.k) vVar;
                kVar.b(androidx.compose.ui.semantics.j.b, new androidx.compose.ui.semantics.a(null, new V(0, function0)));
                break;
            default:
                androidx.compose.ui.semantics.v vVar2 = (androidx.compose.ui.semantics.v) obj;
                kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.u uVar = androidx.compose.ui.semantics.r.n;
                kotlin.reflect.n nVar = androidx.compose.ui.semantics.t.a[9];
                uVar.a(vVar2, Float.valueOf(1.0f));
                androidx.compose.ui.semantics.t.e(vVar2, str);
                androidx.compose.ui.semantics.k kVar2 = (androidx.compose.ui.semantics.k) vVar2;
                kVar2.b(androidx.compose.ui.semantics.j.b, new androidx.compose.ui.semantics.a(null, new V(2, function0)));
                break;
        }
        return Unit.a;
    }
}
