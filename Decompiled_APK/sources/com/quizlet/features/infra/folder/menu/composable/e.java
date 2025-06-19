package com.quizlet.features.infra.folder.menu.composable;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.assembly.compose.modals.x;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ x j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(x xVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = xVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        x.d(this.j);
        return Unit.a;
    }
}
