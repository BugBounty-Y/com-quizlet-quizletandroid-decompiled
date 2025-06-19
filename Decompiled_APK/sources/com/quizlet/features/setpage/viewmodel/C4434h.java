package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.db.data.models.persisted.DBStudySet;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.setpage.viewmodel.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4434h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;
    public final /* synthetic */ DBStudySet l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4434h(P p, DBStudySet dBStudySet, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
        this.l = dBStudySet;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4434h(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4434h) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        P p = this.k;
        if (i == 0) {
            Z.e(obj);
            androidx.work.impl.model.n nVar = p.m;
            this.j = 1;
            obj = nVar.c(this.l, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.features.setpage.usecases.g gVar = (com.quizlet.features.setpage.usecases.g) obj;
        if (gVar == com.quizlet.features.setpage.usecases.g.c) {
            p.k1.j(com.quizlet.features.setpage.screenstates.D.a);
        } else if (gVar == com.quizlet.features.setpage.usecases.g.a) {
            p.k1.j(com.quizlet.features.setpage.screenstates.C.a);
        }
        return Unit.a;
    }
}
