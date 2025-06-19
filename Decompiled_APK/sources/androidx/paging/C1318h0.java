package androidx.paging;

import androidx.compose.foundation.text.input.internal.C0496b;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.paging.h0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1318h0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C1336q0 k;
    public final /* synthetic */ kotlinx.coroutines.channels.h l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C1318h0(C1336q0 c1336q0, kotlin.coroutines.h hVar, kotlinx.coroutines.channels.h hVar2) {
        super(2, hVar);
        this.k = c1336q0;
        this.l = hVar2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C1318h0(this.k, hVar, this.l);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C1318h0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C1329n c1329n = this.k.d;
            C0496b c0496b = new C0496b(this.l, 6);
            this.j = 1;
            if (c1329n.b(c0496b, this) == aVar) {
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
