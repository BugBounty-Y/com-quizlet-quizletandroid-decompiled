package androidx.compose.foundation;

import androidx.compose.foundation.gestures.AbstractC0349s0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0454m extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0456n l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0454m(C0456n c0456n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0456n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0454m c0454m = new C0454m(this.l, hVar);
        c0454m.k = obj;
        return c0454m;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0454m) create((androidx.compose.ui.input.pointer.B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.compose.ui.input.pointer.B b = (androidx.compose.ui.input.pointer.B) this.k;
            C0372l c0372l = new C0372l(this.l, null);
            this.j = 1;
            if (AbstractC0349s0.d(b, c0372l, this) == aVar) {
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
