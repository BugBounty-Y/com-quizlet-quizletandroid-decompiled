package com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public final /* synthetic */ g j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(g gVar, h hVar) {
        super(2, hVar);
        this.j = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        g gVar = this.j;
        com.quizlet.infra.legacysyncengine.features.properties.d.c(gVar.b, gVar.j.u);
        return Unit.a;
    }
}
