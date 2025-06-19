package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class g1 extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ kotlinx.coroutines.C m;
    public final /* synthetic */ Function1 n;
    public final /* synthetic */ kotlin.jvm.internal.J o;
    public final /* synthetic */ C0326g0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g1(kotlinx.coroutines.C c, androidx.compose.foundation.H h, Function1 function1, kotlin.jvm.internal.J j, C0326g0 c0326g0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = c;
        this.n = function1;
        this.o = j;
        this.p = c0326g0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0326g0 c0326g0 = this.p;
        g1 g1Var = new g1(this.m, null, this.n, this.o, c0326g0, hVar);
        g1Var.l = obj;
        return g1Var;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g1) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.ui.input.pointer.z zVar = (androidx.compose.ui.input.pointer.z) this.l;
            this.k = 1;
            obj = k1.e(zVar, androidx.compose.ui.input.pointer.g.b, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        androidx.compose.ui.input.pointer.n nVar = (androidx.compose.ui.input.pointer.n) obj;
        C0326g0 c0326g0 = this.p;
        kotlinx.coroutines.C c = this.m;
        if (nVar != null) {
            nVar.a();
            kotlinx.coroutines.E.A(c, null, null, new e1(c0326g0, null), 3);
            throw null;
        }
        kotlinx.coroutines.E.A(c, null, null, new f1(c0326g0, null), 3);
        Function1 function1 = this.n;
        if (function1 == null) {
            return null;
        }
        function1.invoke(new androidx.compose.ui.geometry.b(((androidx.compose.ui.input.pointer.n) this.o.a).c));
        return Unit.a;
    }
}
