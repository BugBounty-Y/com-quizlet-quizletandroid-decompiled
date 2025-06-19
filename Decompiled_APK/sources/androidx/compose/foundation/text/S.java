package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class S extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ u0 l;
    public final /* synthetic */ androidx.compose.foundation.text.selection.i0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S(u0 u0Var, androidx.compose.foundation.text.selection.i0 i0Var, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = u0Var;
        this.m = i0Var;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        S s = new S(this.l, this.m, hVar);
        s.k = obj;
        return s;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((S) create((androidx.compose.ui.input.pointer.B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Q q = new Q((androidx.compose.ui.input.pointer.B) this.k, this.l, this.m, null);
            this.j = 1;
            if (kotlinx.coroutines.E.m(q, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
