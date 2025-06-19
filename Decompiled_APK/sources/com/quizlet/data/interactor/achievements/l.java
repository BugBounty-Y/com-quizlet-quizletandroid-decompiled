package com.quizlet.data.interactor.achievements;

import androidx.glance.appwidget.protobuf.Z;
import com.google.firebase.messaging.p;
import com.quizlet.data.model.h2;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ p k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(p pVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = pVar;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new l(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
        this.j = 1;
        com.quizlet.data.repository.achievements.h hVar = (com.quizlet.data.repository.achievements.h) this.k.b;
        boolean z = this.l;
        com.quizlet.local.cache.e eVar = ((com.quizlet.local.cache.caches.a) hVar.d).a;
        eVar.getClass();
        Object objJ = (h2) eVar.get(Unit.a);
        if (objJ == null || z) {
            objJ = E.J((AbstractC5040y) hVar.c, new com.quizlet.data.repository.achievements.f(hVar, null), this);
        }
        return objJ == aVar ? aVar : objJ;
    }
}
