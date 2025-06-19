package com.quizlet.features.questiontypes.fitb.ui;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class k extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ boolean j;
    public final /* synthetic */ x k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(x xVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        k kVar = new k(this.k, hVar);
        kVar.j = ((Boolean) obj).booleanValue();
        return kVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Boolean bool = (Boolean) obj;
        bool.booleanValue();
        return ((k) create(bool, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        boolean z = this.j;
        x xVar = this.k;
        if (z) {
            x.d(xVar);
        } else {
            xVar.a();
        }
        return Unit.a;
    }
}
