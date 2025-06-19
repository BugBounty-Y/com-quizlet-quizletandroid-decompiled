package com.quizlet.features.setpage.termlist.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.D1;
import com.quizlet.data.model.E1;
import com.quizlet.data.model.p2;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.features.setpage.termlist.data.n;
import com.quizlet.features.setpage.termlist.data.p;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ j k;
    public final /* synthetic */ long l;
    public final /* synthetic */ boolean m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(j jVar, long j, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = jVar;
        this.l = j;
        this.m = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Set set;
        s0 s0Var;
        Object value;
        p pVar;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        j jVar = this.k;
        if (i == 0) {
            Z.e(obj);
            com.google.android.gms.internal.appset.e eVar = jVar.b;
            this.j = 1;
            com.quizlet.data.repository.widget.b bVar = (com.quizlet.data.repository.widget.b) eVar.c;
            long personId = ((UserInfoCache) bVar.c).getPersonId();
            com.quizlet.data.repository.selectedterm.f fVar = (com.quizlet.data.repository.selectedterm.f) bVar.b;
            obj = E.J(fVar.c, new com.quizlet.data.repository.selectedterm.e(fVar, this.l, jVar.g, personId, this.m, null), this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        List<D1> list = (List) obj;
        Object value2 = jVar.h.getValue();
        n nVar = value2 instanceof n ? (n) value2 : null;
        if (nVar == null || (set = nVar.c) == null) {
            return Unit.a;
        }
        LinkedHashSet linkedHashSetZ0 = CollectionsKt.z0(set);
        for (D1 d1 : list) {
            if (d1 instanceof E1) {
                linkedHashSetZ0.add(new Long(((E1) d1).a));
            } else {
                if (!(d1 instanceof p2)) {
                    throw new NoWhenBranchMatchedException();
                }
                linkedHashSetZ0.remove(new Long(((p2) d1).a));
            }
        }
        do {
            s0Var = jVar.h;
            value = s0Var.getValue();
            pVar = (p) value;
            Intrinsics.e(pVar, "null cannot be cast to non-null type com.quizlet.features.setpage.termlist.data.TermsViewState.Content");
        } while (!s0Var.k(value, n.a((n) pVar, null, linkedHashSetZ0, null, false, 27)));
        return Unit.a;
    }
}
