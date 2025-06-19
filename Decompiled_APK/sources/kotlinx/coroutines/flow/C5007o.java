package kotlinx.coroutines.flow;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.internal.AbstractC4994b;

/* renamed from: kotlinx.coroutines.flow.o, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5007o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlin.jvm.internal.J j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ kotlin.jvm.internal.J m;
    public final /* synthetic */ InterfaceC5002j n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5007o(kotlin.coroutines.h hVar, kotlin.jvm.internal.J j, InterfaceC5002j interfaceC5002j) {
        super(2, hVar);
        this.m = j;
        this.n = interfaceC5002j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C5007o c5007o = new C5007o(hVar, this.m, this.n);
        c5007o.l = obj;
        return c5007o;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C5007o) create(new kotlinx.coroutines.channels.o(((kotlinx.coroutines.channels.o) obj).a), (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.jvm.internal.J j;
        kotlin.jvm.internal.J j2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Object obj2 = ((kotlinx.coroutines.channels.o) this.l).a;
            boolean z = obj2 instanceof kotlinx.coroutines.channels.n;
            j = this.m;
            if (!z) {
                j.a = obj2;
            }
            if (z) {
                Throwable thA = kotlinx.coroutines.channels.o.a(obj2);
                if (thA != null) {
                    throw thA;
                }
                Object obj3 = j.a;
                if (obj3 != null) {
                    if (obj3 == AbstractC4994b.b) {
                        obj3 = null;
                    }
                    this.l = obj2;
                    this.j = j;
                    this.k = 1;
                    if (this.n.emit(obj3, this) == aVar) {
                        return aVar;
                    }
                    j2 = j;
                }
                j.a = AbstractC4994b.d;
            }
            return Unit.a;
        }
        if (i != 1) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        j2 = this.j;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        j = j2;
        j.a = AbstractC4994b.d;
        return Unit.a;
    }
}
