package com.quizlet.data.repository.user;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.user.UserResponse;
import com.quizlet.remote.service.E;
import io.reactivex.rxjava3.core.p;
import io.reactivex.rxjava3.internal.operators.single.g;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import retrofit2.K;

/* loaded from: classes2.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;
    public final /* synthetic */ Integer n;
    public final /* synthetic */ int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(e eVar, String str, String str2, Integer num, int i, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = str;
        this.m = str2;
        this.n = num;
        this.o = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
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
        com.quizlet.data.repository.course.membership.c cVar = (com.quizlet.data.repository.course.membership.c) ((com.quizlet.data.repository.explanations.myexplanations.a) this.k.b).c;
        String query = this.l;
        Intrinsics.checkNotNullParameter(query, "query");
        com.quizlet.quizletandroid.ui.activitycenter.views.i iVar = (com.quizlet.quizletandroid.ui.activitycenter.views.i) cVar.a;
        Intrinsics.checkNotNullParameter(query, "query");
        p<K<ApiThreeWrapper<UserResponse>>> pVarB = ((E) iVar.b).b(query, this.m, this.n, this.o);
        Intrinsics.checkNotNullParameter(pVarB, "<this>");
        com.quizlet.quizletandroid.ui.activitycenter.models.a mapper = (com.quizlet.quizletandroid.ui.activitycenter.models.a) cVar.b;
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        com.quizlet.quizletandroid.ui.folder.logging.a pagingMapper = (com.quizlet.quizletandroid.ui.folder.logging.a) cVar.c;
        Intrinsics.checkNotNullParameter(pagingMapper, "pagingMapper");
        g gVarG = pVarB.g(new com.quizlet.local.ormlite.models.term.b(mapper, pagingMapper));
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        this.j = 1;
        Object objB = I1.b(gVarG, this);
        return objB == aVar ? aVar : objB;
    }
}
