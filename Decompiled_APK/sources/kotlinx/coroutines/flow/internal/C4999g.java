package kotlinx.coroutines.flow.internal;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: kotlinx.coroutines.flow.internal.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4999g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ AbstractC5000h l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4999g(AbstractC5000h abstractC5000h, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = abstractC5000h;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4999g c4999g = new C4999g(this.l, hVar);
        c4999g.k = obj;
        return c4999g;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4999g) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            InterfaceC5002j interfaceC5002j = (InterfaceC5002j) this.k;
            this.j = 1;
            if (this.l.k(interfaceC5002j, this) == aVar) {
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
