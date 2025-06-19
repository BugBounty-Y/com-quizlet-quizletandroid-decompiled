package androidx.compose.foundation.pager;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.pager.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0471j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ C0466e l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0471j(C0466e c0466e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = c0466e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0471j c0471j = new C0471j(this.l, hVar);
        c0471j.k = obj;
        return c0471j;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0471j) create((androidx.compose.ui.input.pointer.B) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C0470i c0470i = new C0470i((androidx.compose.ui.input.pointer.B) this.k, this.l, null);
            this.j = 1;
            if (kotlinx.coroutines.E.m(c0470i, this) == aVar) {
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
