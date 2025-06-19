package com.quizlet.features.flashcards;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ androidx.lifecycle.J j;
    public final /* synthetic */ S k;
    public final /* synthetic */ com.quizlet.features.flashcards.autoplay.o l;
    public final /* synthetic */ Context m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(Context context, androidx.lifecycle.J j, S s, com.quizlet.features.flashcards.autoplay.o oVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = j;
        this.k = s;
        this.l = oVar;
        this.m = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new t(this.m, this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        androidx.lifecycle.E eH = p0.h(this.j);
        S s = this.k;
        com.quizlet.features.flashcards.autoplay.o oVar = this.l;
        kotlinx.coroutines.E.A(eH, null, null, new C4244s(this.m, this.j, s, oVar, null), 3);
        return Unit.a;
    }
}
