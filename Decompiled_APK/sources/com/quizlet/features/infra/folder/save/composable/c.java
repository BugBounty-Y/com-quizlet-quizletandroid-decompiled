package com.quizlet.features.infra.folder.save.composable;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.infra.folder.menu.data.x;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public final /* synthetic */ com.quizlet.features.infra.folder.save.viewmodel.c j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.quizlet.features.infra.folder.save.viewmodel.c cVar, h hVar) {
        super(2, hVar);
        this.j = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((x) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.j.A();
        return Unit.a;
    }
}
