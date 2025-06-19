package com.quizlet.qutils.coroutines;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.ui.common.ads.D;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.q;
import kotlin.r;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ D l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(D d, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = d;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        k kVar = new k(this.l, hVar);
        kVar.k = obj;
        return kVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((k) create(new r(((r) obj).a), (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            Object obj2 = ((r) this.k).a;
            if (!(obj2 instanceof q)) {
                Z.e(obj2);
                this.j = 1;
                if (this.l.invoke(obj2, this) == aVar) {
                    return aVar;
                }
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
