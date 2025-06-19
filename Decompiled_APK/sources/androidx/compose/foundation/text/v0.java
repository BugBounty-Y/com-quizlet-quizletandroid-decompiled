package androidx.compose.foundation.text;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class v0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.foundation.text.input.internal.n k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public v0(androidx.compose.foundation.text.input.internal.n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new v0(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((v0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            this.j = 1;
            androidx.compose.foundation.text.input.internal.n nVar = this.k;
            nVar.getClass();
            Object objM = kotlinx.coroutines.E.m(new androidx.compose.foundation.text.input.internal.m(nVar, null), this);
            if (objM != obj2) {
                objM = Unit.a;
            }
            if (objM == obj2) {
                return obj2;
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
