package androidx.compose.foundation.text.selection;

import androidx.compose.animation.core.C0238e;
import androidx.compose.foundation.text.C0494i0;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.W0;
import androidx.datastore.core.C1087t;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class N extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ W0 l;
    public final /* synthetic */ C0238e m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N(W0 w0, C0238e c0238e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = w0;
        this.m = c0238e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        N n = new N(this.l, this.m, hVar);
        n.k = obj;
        return n;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((N) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            C1087t c1087tF = C0776c.F(new L(this.l, 0));
            C0494i0 c0494i0 = new C0494i0(1, this.m, c);
            this.j = 1;
            if (c1087tF.b(c0494i0, this) == aVar) {
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
