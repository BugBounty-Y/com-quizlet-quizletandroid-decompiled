package androidx.compose.foundation.layout;

import androidx.compose.animation.core.C0242g;
import androidx.compose.foundation.C0473q;
import androidx.compose.material3.F3;
import androidx.compose.material3.G3;
import androidx.compose.runtime.InterfaceC0773a0;
import java.io.Serializable;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.foundation.layout.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0413u extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Serializable e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0413u(Object obj, Object obj2, Object obj3, Serializable serializable, Object obj4, Object obj5, int i) {
        super(1);
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = serializable;
        this.f = obj4;
        this.g = obj5;
    }

    /* JADX WARN: Type inference failed for: r2v3, types: [java.lang.Object, java.util.Map] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Serializable serializable = this.e;
        Object obj2 = this.d;
        Object obj3 = this.g;
        Object obj4 = this.b;
        Object obj5 = this.c;
        Object obj6 = this.f;
        boolean z = true;
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
                androidx.compose.ui.layout.W[] wArr = (androidx.compose.ui.layout.W[]) obj4;
                int length = wArr.length;
                int i = 0;
                int i2 = 0;
                while (i < length) {
                    int i3 = i;
                    androidx.compose.ui.layout.W w = wArr[i3];
                    Intrinsics.e(w, "null cannot be cast to non-null type androidx.compose.ui.layout.Placeable");
                    AbstractC0409s.b(v, w, (androidx.compose.ui.layout.J) ((List) obj5).get(i2), ((androidx.compose.ui.layout.M) obj2).getLayoutDirection(), ((kotlin.jvm.internal.H) serializable).a, ((kotlin.jvm.internal.H) obj6).a, ((C0415v) obj3).a);
                    i = i3 + 1;
                    i2++;
                    z = z;
                }
                break;
            default:
                androidx.compose.material.V v2 = new androidx.compose.material.V(1, (Function0) obj6);
                kotlin.reflect.n[] nVarArr = androidx.compose.ui.semantics.t.a;
                androidx.compose.ui.semantics.k kVar = (androidx.compose.ui.semantics.k) ((androidx.compose.ui.semantics.v) obj);
                kVar.b(androidx.compose.ui.semantics.j.t, new androidx.compose.ui.semantics.a((String) obj5, v2));
                F3 f3 = (F3) obj4;
                G3 g3 = (G3) ((androidx.compose.runtime.L0) ((InterfaceC0773a0) f3.b.g)).getValue();
                G3 g32 = G3.c;
                kotlinx.coroutines.C c = (kotlinx.coroutines.C) obj3;
                if (g3 == g32) {
                    kVar.b(androidx.compose.ui.semantics.j.r, new androidx.compose.ui.semantics.a((String) obj2, new C0473q(f3, c, f3, 9)));
                } else if (f3.b.h().a.containsKey(g32)) {
                    kVar.b(androidx.compose.ui.semantics.j.s, new androidx.compose.ui.semantics.a((String) serializable, new C0242g(13, f3, c)));
                }
                break;
        }
        return Unit.a;
    }
}
