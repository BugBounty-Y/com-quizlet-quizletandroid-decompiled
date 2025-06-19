package com.quizlet.features.folders.composables;

import android.content.Context;
import com.quizlet.features.folders.data.C4299o0;
import com.quizlet.features.folders.data.InterfaceC4312v0;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.features.folders.navigation.b k;
    public final /* synthetic */ InterfaceC4312v0 l;
    public final /* synthetic */ Context m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(com.quizlet.features.folders.navigation.b bVar, InterfaceC4312v0 interfaceC4312v0, Context context, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = bVar;
        this.l = interfaceC4312v0;
        this.m = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C4299o0 c4299o0 = (C4299o0) this.l;
            StudyableModelData.StudyFolder studyFolder = c4299o0.a;
            String strA = c4299o0.b.a(this.m);
            this.j = 1;
            if (this.k.a(studyFolder, strA, -1L, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
