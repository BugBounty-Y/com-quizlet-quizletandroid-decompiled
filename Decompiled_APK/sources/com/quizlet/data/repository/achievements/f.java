package com.quizlet.data.repository.achievements;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.C4121d2;
import com.quizlet.data.model.e2;
import com.quizlet.data.model.f2;
import com.quizlet.data.model.g2;
import com.quizlet.data.model.h2;
import com.quizlet.remote.service.InterfaceC4774a;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class f extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        h hVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.google.android.gms.internal.appset.e eVar = (com.google.android.gms.internal.appset.e) hVar.a;
            this.j = 1;
            obj = eVar.p(((InterfaceC4774a) eVar.b).c(true), new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(7), new com.quizlet.qutils.android.f(6), new com.quizlet.remote.model.achievements.a(eVar, 4), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        h2 h2Var = (h2) obj;
        if ((h2Var instanceof C4121d2) || (h2Var instanceof e2) || (h2Var instanceof g2)) {
            com.quizlet.local.cache.e eVar2 = ((com.quizlet.local.cache.caches.a) hVar.d).a;
            eVar2.getClass();
            eVar2.a(Unit.a, h2Var);
            return h2Var;
        }
        if (!(h2Var instanceof f2)) {
            throw new NoWhenBranchMatchedException();
        }
        ((org.slf4j.b) hVar.b).m("Remote error trying to get StudyStreak: " + ((f2) h2Var).a.getMessage());
        return h2Var;
    }
}
