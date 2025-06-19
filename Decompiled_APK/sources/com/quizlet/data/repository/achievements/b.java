package com.quizlet.data.repository.achievements;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.AbstractC4140k;
import com.quizlet.data.model.C4131h;
import com.quizlet.data.model.C4134i;
import com.quizlet.data.model.C4137j;
import com.quizlet.remote.service.InterfaceC4774a;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
            obj = eVar.p(((InterfaceC4774a) eVar.b).e(), new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(5), new com.quizlet.qutils.android.f(3), new com.quizlet.remote.model.achievements.a(eVar, 1), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        AbstractC4140k abstractC4140k = (AbstractC4140k) obj;
        if ((abstractC4140k instanceof C4131h) || (abstractC4140k instanceof C4137j)) {
            com.quizlet.local.cache.e eVar2 = ((com.quizlet.local.cache.caches.a) hVar.d).c;
            eVar2.getClass();
            eVar2.a(Unit.a, abstractC4140k);
            return abstractC4140k;
        }
        if (!(abstractC4140k instanceof C4134i)) {
            throw new NoWhenBranchMatchedException();
        }
        ((org.slf4j.b) hVar.b).m("Remote error trying to get AchievementBadges: " + ((C4134i) abstractC4140k).a.getMessage());
        return abstractC4140k;
    }
}
