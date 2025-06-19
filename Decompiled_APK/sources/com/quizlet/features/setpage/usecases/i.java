package com.quizlet.features.setpage.usecases;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.n;
import com.quizlet.db.data.models.persisted.DBStudySet;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ n k;
    public final /* synthetic */ DBStudySet l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(n nVar, DBStudySet dBStudySet, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = nVar;
        this.l = dBStudySet;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        this.j = 1;
        Enum enumC = this.k.c(this.l, this);
        return enumC == aVar ? aVar : enumC;
    }
}
