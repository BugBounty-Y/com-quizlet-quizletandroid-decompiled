package kotlinx.coroutines.flow;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: kotlinx.coroutines.flow.m, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5005m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ InterfaceC4992i k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5005m(InterfaceC4992i interfaceC4992i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = interfaceC4992i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C5005m(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C5005m) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            this.j = 1;
            Object objB = this.k.b(kotlinx.coroutines.flow.internal.B.a, this);
            if (objB != aVar) {
                objB = Unit.a;
            }
            if (objB == aVar) {
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
