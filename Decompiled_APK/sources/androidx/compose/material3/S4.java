package androidx.compose.material3;

import androidx.compose.animation.core.C0238e;
import androidx.compose.animation.core.InterfaceC0256n;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class S4 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ U4 k;
    public final /* synthetic */ float l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public S4(U4 u4, float f, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = u4;
        this.l = f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new S4(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((S4) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            U4 u4 = this.k;
            C0238e c0238e = u4.q;
            if (c0238e != null) {
                Float f = new Float(this.l);
                InterfaceC0256n interfaceC0256n = u4.p ? AbstractC0679l4.f : AbstractC0679l4.g;
                this.j = 1;
                obj = C0238e.c(c0238e, f, interfaceC0256n, null, this, 12);
                if (obj == aVar) {
                    return aVar;
                }
            }
            return Unit.a;
        }
        if (i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        androidx.glance.appwidget.protobuf.Z.e(obj);
        return Unit.a;
    }
}
