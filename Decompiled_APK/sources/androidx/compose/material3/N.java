package androidx.compose.material3;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes.dex */
public final class N extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.foundation.interaction.l k;
    public final /* synthetic */ androidx.compose.runtime.snapshots.q l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public N(androidx.compose.foundation.interaction.l lVar, androidx.compose.runtime.snapshots.q qVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = lVar;
        this.l = qVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new N(this.k, this.l, hVar);
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
            InterfaceC4992i interfaceC4992iB = this.k.b();
            M m = new M(this.l, 0);
            this.j = 1;
            if (interfaceC4992iB.b(m, this) == aVar) {
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
