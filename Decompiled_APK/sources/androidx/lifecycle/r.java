package androidx.lifecycle;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ Y j;
    public final /* synthetic */ androidx.camera.camera2.internal.D k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(Y y, androidx.camera.camera2.internal.D d, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = y;
        this.k = d;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        this.j.g(this.k);
        return Unit.a;
    }
}
