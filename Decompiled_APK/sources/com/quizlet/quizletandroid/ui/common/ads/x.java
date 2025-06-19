package com.quizlet.quizletandroid.ui.common.ads;

import androidx.glance.appwidget.protobuf.Z;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;

/* loaded from: classes3.dex */
public final class x extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ J k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(J j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        x xVar = new x(this.k, hVar);
        xVar.j = obj;
        return xVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((x) create((Map) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.k.a = (Map) this.j;
        return Unit.a;
    }
}
