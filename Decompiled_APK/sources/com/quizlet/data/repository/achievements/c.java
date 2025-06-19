package com.quizlet.data.repository.achievements;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.AbstractC4163s;
import com.quizlet.data.model.C4155p;
import com.quizlet.data.model.C4158q;
import com.quizlet.data.model.r;
import com.quizlet.remote.service.InterfaceC4774a;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;
    public final /* synthetic */ int l;
    public final /* synthetic */ int m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(h hVar, int i, int i2, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
        this.l = i;
        this.m = i2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
            obj = eVar.p(((InterfaceC4774a) eVar.b).d(this.m, this.l), new com.quizlet.quizletandroid.ui.startpage.nav2.composables.b(6), new com.quizlet.qutils.android.f(5), new com.quizlet.remote.model.achievements.a(eVar, 3), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        AbstractC4163s abstractC4163s = (AbstractC4163s) obj;
        if ((abstractC4163s instanceof C4155p) || (abstractC4163s instanceof r)) {
            com.quizlet.local.cache.e eVar2 = ((com.quizlet.local.cache.caches.a) hVar.d).b;
            eVar2.getClass();
            eVar2.a(Unit.a, abstractC4163s);
            return abstractC4163s;
        }
        if (!(abstractC4163s instanceof C4158q)) {
            throw new NoWhenBranchMatchedException();
        }
        ((org.slf4j.b) hVar.b).m("Remote error trying to get AchievementsHistory: " + ((C4158q) abstractC4163s).a.getMessage());
        return abstractC4163s;
    }
}
