package androidx.compose.material.navigation;

import androidx.compose.runtime.C0807l0;
import androidx.compose.runtime.L0;
import androidx.datastore.core.C1087t;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ i l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        h hVar2 = new h(this.l, hVar);
        hVar2.k = obj;
        return hVar2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C0807l0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C0807l0 c0807l0 = (C0807l0) this.k;
            i iVar = this.l;
            C1087t c1087t = new C1087t(new g(((Boolean) ((L0) iVar.d).getValue()).booleanValue() ? iVar.b().e : e0.c(K.a), null, iVar));
            e eVar = new e(c0807l0, 0);
            this.j = 1;
            if (c1087t.b(eVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
