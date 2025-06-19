package com.quizlet.data.repository.achievements;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.AbstractC4152o;
import com.quizlet.data.model.C4143l;
import com.quizlet.data.model.C4146m;
import com.quizlet.data.model.C4149n;
import com.quizlet.remote.service.InterfaceC4774a;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class e extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
            obj = eVar.p(((InterfaceC4774a) eVar.b).b(), new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(8), new com.quizlet.qutils.android.f(2), new com.quizlet.remote.model.achievements.a(eVar, 0), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        AbstractC4152o abstractC4152o = (AbstractC4152o) obj;
        if (abstractC4152o instanceof C4143l) {
            com.quizlet.local.cache.caches.a aVar2 = (com.quizlet.local.cache.caches.a) hVar.d;
            aVar2.a.b.clear();
            aVar2.b.b.clear();
            aVar2.c.b.clear();
            aVar2.d.b.clear();
            return abstractC4152o;
        }
        if (!(abstractC4152o instanceof C4146m)) {
            if (abstractC4152o instanceof C4149n) {
                return abstractC4152o;
            }
            throw new NoWhenBranchMatchedException();
        }
        ((org.slf4j.b) hVar.b).m("Remote error trying to get AchievementNotification: " + ((C4146m) abstractC4152o).a.getMessage());
        return abstractC4152o;
    }
}
