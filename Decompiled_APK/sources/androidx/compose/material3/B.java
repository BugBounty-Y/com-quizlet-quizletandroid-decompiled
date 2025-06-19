package androidx.compose.material3;

import androidx.compose.animation.core.C0276z;
import androidx.compose.animation.core.InterfaceC0256n;
import kotlin.Unit;

/* loaded from: classes.dex */
public final class B extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public int j;
    public /* synthetic */ float k;
    public final /* synthetic */ com.quizlet.data.repository.achievements.h l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(com.quizlet.data.repository.achievements.h hVar, kotlin.coroutines.h hVar2) {
        super(3, hVar2);
        this.l = hVar;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        float fFloatValue = ((Number) obj2).floatValue();
        B b = new B(this.l, (kotlin.coroutines.h) obj3);
        b.k = fFloatValue;
        return b.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            float f = this.k;
            com.quizlet.data.repository.achievements.h hVar = this.l;
            X4 x4 = (X4) hVar.a;
            this.j = 1;
            if (D.h(x4, f, (C0276z) hVar.c, (InterfaceC0256n) hVar.b, this) == aVar) {
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
