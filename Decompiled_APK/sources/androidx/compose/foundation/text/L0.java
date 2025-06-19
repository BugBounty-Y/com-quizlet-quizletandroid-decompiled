package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class L0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0502j0 k;
    public final /* synthetic */ androidx.compose.foundation.interaction.l l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L0(C0502j0 c0502j0, androidx.compose.foundation.interaction.l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0502j0;
        this.l = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new L0(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            this.j = 1;
            C0502j0 c0502j0 = this.k;
            c0502j0.getClass();
            Object objB = this.l.b().b(new C0494i0(0, new androidx.collection.G(), c0502j0), this);
            if (objB != aVar) {
                objB = Unit.a;
            }
            if (objB == aVar) {
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
