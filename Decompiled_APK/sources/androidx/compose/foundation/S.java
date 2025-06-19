package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class S extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.foundation.interaction.l k;
    public final /* synthetic */ androidx.compose.foundation.interaction.j l;
    public final /* synthetic */ kotlinx.coroutines.Q m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S(androidx.compose.foundation.interaction.l lVar, androidx.compose.foundation.interaction.j jVar, kotlinx.coroutines.Q q, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = lVar;
        this.l = jVar;
        this.m = q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new S(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((S) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            this.j = 1;
            if (this.k.c(this.l, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        kotlinx.coroutines.Q q = this.m;
        if (q != null) {
            q.dispose();
        }
        return Unit.a;
    }
}
