package androidx.compose.material3;

import androidx.compose.foundation.text.C0494i0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes.dex */
public final class T4 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ U4 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public T4(U4 u4, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = u4;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new T4(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((T4) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlin.jvm.internal.H h = new kotlin.jvm.internal.H();
            U4 u4 = this.k;
            InterfaceC4992i interfaceC4992iB = u4.n.b();
            C0494i0 c0494i0 = new C0494i0(5, h, u4);
            this.j = 1;
            if (interfaceC4992iB.b(c0494i0, this) == aVar) {
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
