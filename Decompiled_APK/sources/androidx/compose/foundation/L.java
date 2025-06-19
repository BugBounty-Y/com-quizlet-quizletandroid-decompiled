package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* loaded from: classes.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ M k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public L(M m, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new L(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlin.jvm.internal.H h = new kotlin.jvm.internal.H();
            kotlin.jvm.internal.H h2 = new kotlin.jvm.internal.H();
            kotlin.jvm.internal.H h3 = new kotlin.jvm.internal.H();
            M m = this.k;
            InterfaceC4992i interfaceC4992iB = m.n.b();
            K k = new K(h, h2, h3, m, 0);
            this.j = 1;
            if (interfaceC4992iB.b(k, this) == aVar) {
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
