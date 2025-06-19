package com.quizlet.data.interactor.achievements;

import androidx.glance.appwidget.protobuf.Z;
import com.google.firebase.messaging.p;
import com.quizlet.data.model.AbstractC4163s;
import java.time.LocalDate;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ p k;
    public final /* synthetic */ LocalDate l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(p pVar, LocalDate localDate, kotlin.coroutines.h hVar, boolean z) {
        super(2, hVar);
        this.k = pVar;
        this.l = localDate;
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.k, this.l, hVar, this.m);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
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
        LocalDate localDate = this.l;
        int monthValue = localDate.getMonthValue();
        int year = localDate.getYear();
        this.j = 1;
        com.quizlet.data.repository.achievements.h hVar = (com.quizlet.data.repository.achievements.h) this.k.b;
        boolean z = this.m;
        com.quizlet.local.cache.e eVar = ((com.quizlet.local.cache.caches.a) hVar.d).b;
        eVar.getClass();
        Object objJ = (AbstractC4163s) eVar.get(Unit.a);
        if (objJ == null || z) {
            objJ = E.J((AbstractC5040y) hVar.c, new com.quizlet.data.repository.achievements.c(hVar, monthValue, year, null), this);
        }
        return objJ == aVar ? aVar : objJ;
    }
}
