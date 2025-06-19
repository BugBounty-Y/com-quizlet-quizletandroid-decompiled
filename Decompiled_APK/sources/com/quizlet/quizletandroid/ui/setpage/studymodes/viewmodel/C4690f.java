package com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.StudySet;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.f, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4690f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ s j;
    public final /* synthetic */ long k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4690f(s sVar, long j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = sVar;
        this.k = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4690f(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4690f) create((StudySet) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        return new com.quizlet.features.infra.basestudy.data.models.p(this.j.j.c(this.k, com.quizlet.features.blocks.data.b.c));
    }
}
