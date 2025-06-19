package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0366i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ AbstractC0368j l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0366i(AbstractC0368j abstractC0368j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = abstractC0368j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0366i c0366i = new C0366i(this.l, hVar);
        c0366i.k = obj;
        return c0366i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0366i) create((androidx.compose.ui.input.pointer.B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.ui.input.pointer.B b = (androidx.compose.ui.input.pointer.B) this.k;
            this.j = 1;
            if (this.l.Q0(b, this) == aVar) {
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
