package androidx.compose.foundation.pager;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0466e k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(C0466e c0466e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0466e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new s(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((s) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object objF;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            float f = I.a;
            C0466e c0466e = this.k;
            if (c0466e.j() + 1 >= c0466e.l() || (objF = c0466e.f(c0466e.j() + 1, AbstractC0240f.q(7, null), this)) != aVar) {
                objF = Unit.a;
            }
            if (objF == aVar) {
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
