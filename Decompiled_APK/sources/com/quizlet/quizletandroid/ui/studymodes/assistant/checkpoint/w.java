package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ J j;
    public final /* synthetic */ com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(J j, com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.b bVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = j;
        this.k = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new w(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((w) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        J j = this.j;
        E.A(p0.h(j), null, null, new v(j, this.k, null), 3);
        return Unit.a;
    }
}
