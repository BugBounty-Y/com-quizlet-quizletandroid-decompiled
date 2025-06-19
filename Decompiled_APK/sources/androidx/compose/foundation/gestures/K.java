package androidx.compose.foundation.gestures;

import androidx.compose.animation.C0278e;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Q l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(Q q, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        K k = new K(this.l, hVar);
        k.k = obj;
        return k;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((androidx.compose.ui.input.pointer.B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.ui.input.pointer.B b = (androidx.compose.ui.input.pointer.B) this.k;
            com.quizlet.data.interactor.course.e eVar = new com.quizlet.data.interactor.course.e();
            Q q = this.l;
            I i2 = new I(q, b, new androidx.compose.animation.D(3, q, eVar), new C0278e(11, eVar, q), new J(q, 0), new J(q, 1), new androidx.compose.foundation.contextmenu.i(3, eVar, q), null);
            this.j = 1;
            if (kotlinx.coroutines.E.m(i2, this) == aVar) {
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
