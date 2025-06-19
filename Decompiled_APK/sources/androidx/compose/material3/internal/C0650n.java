package androidx.compose.material3.internal;

import androidx.compose.material.C0574q;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.internal.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0650n extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ androidx.work.impl.model.t k;
    public final /* synthetic */ C0574q l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0650n(C0574q c0574q, androidx.work.impl.model.t tVar, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = tVar;
        this.l = c0574q;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new C0650n(this.l, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C0650n) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            androidx.work.impl.model.t tVar = this.k;
            C0648l c0648l = new C0648l(tVar, 0);
            C0649m c0649m = new C0649m(this.l, tVar, null);
            this.j = 1;
            if (AbstractC0646j.b(c0648l, c0649m, this) == aVar) {
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
