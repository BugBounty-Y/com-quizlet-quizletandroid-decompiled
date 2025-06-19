package com.quizlet.features.questiontypes.basequestion;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.studiablemodels.grading.StudiableQuestionGradedAnswer;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ boolean k;
    public final /* synthetic */ StudiableQuestionGradedAnswer l;
    public final /* synthetic */ kotlin.coroutines.jvm.internal.i m;
    public final /* synthetic */ com.quizlet.quizletandroid.managers.audio.h n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public b(boolean z, StudiableQuestionGradedAnswer studiableQuestionGradedAnswer, Function2 function2, com.quizlet.quizletandroid.managers.audio.h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = z;
        this.l = studiableQuestionGradedAnswer;
        this.m = (kotlin.coroutines.jvm.internal.i) function2;
        this.n = hVar;
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        b bVar = new b(this.k, this.l, this.m, this.n, hVar);
        bVar.j = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.coroutines.jvm.internal.i, kotlin.jvm.functions.Function2] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        return E.A((C) this.j, null, null, new a(this.k, this.l, this.m, this.n, null), 3);
    }
}
