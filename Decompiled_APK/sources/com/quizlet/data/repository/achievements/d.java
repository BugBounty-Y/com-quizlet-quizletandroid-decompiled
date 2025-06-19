package com.quizlet.data.repository.achievements;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.AbstractC4128g;
import com.quizlet.data.model.C4106a;
import com.quizlet.data.model.C4118d;
import com.quizlet.data.model.C4122e;
import com.quizlet.data.model.C4125f;
import com.quizlet.remote.service.InterfaceC4774a;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
            obj = eVar.p(((InterfaceC4774a) eVar.b).g(), new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(4), new com.quizlet.qutils.android.f(4), new com.quizlet.remote.model.achievements.a(eVar, 2), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        AbstractC4128g abstractC4128g = (AbstractC4128g) obj;
        if ((abstractC4128g instanceof C4106a) || (abstractC4128g instanceof C4118d) || (abstractC4128g instanceof C4125f)) {
            com.quizlet.local.cache.e eVar2 = ((com.quizlet.local.cache.caches.a) hVar.d).d;
            eVar2.getClass();
            eVar2.a(Unit.a, abstractC4128g);
            return abstractC4128g;
        }
        if (!(abstractC4128g instanceof C4122e)) {
            throw new NoWhenBranchMatchedException();
        }
        ((org.slf4j.b) hVar.b).m("Remote error trying to get AchievementBadge: " + ((C4122e) abstractC4128g).a.getMessage());
        return abstractC4128g;
    }
}
