package androidx.compose.foundation.pager;

import androidx.compose.foundation.gestures.AbstractC0349s0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.pager.i, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0470i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ androidx.compose.ui.input.pointer.B k;
    public final /* synthetic */ C0466e l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0470i(androidx.compose.ui.input.pointer.B b, C0466e c0466e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = b;
        this.l = c0466e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0470i(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0470i) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C0469h c0469h = new C0469h(this.l, null);
            this.j = 1;
            if (AbstractC0349s0.d(this.k, c0469h, this) == aVar) {
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
