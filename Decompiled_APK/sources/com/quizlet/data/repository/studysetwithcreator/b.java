package com.quizlet.data.repository.studysetwithcreator;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.v;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.data.model.C4186z1;
import com.quizlet.remote.service.B;
import io.reactivex.rxjava3.internal.operators.single.g;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ d k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;
    public final /* synthetic */ Integer n;
    public final /* synthetic */ int o;
    public final /* synthetic */ C4186z1 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(d dVar, String str, String str2, Integer num, int i, C4186z1 c4186z1, h hVar) {
        super(2, hVar);
        this.k = dVar;
        this.l = str;
        this.m = str2;
        this.n = num;
        this.o = i;
        this.p = c4186z1;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, this.n, this.o, this.p, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
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
        com.quizlet.remote.model.union.studysetwithcreator.c cVar = (com.quizlet.remote.model.union.studysetwithcreator.c) ((v) this.k.a).c;
        String query = this.l;
        Intrinsics.checkNotNullParameter(query, "query");
        C4186z1 searchFilters = this.p;
        Intrinsics.checkNotNullParameter(searchFilters, "searchFilters");
        com.quizlet.quizletandroid.ui.common.ads.prebid.creators.c cVar2 = cVar.a;
        Intrinsics.checkNotNullParameter(query, "query");
        Intrinsics.checkNotNullParameter(searchFilters, "searchFilters");
        g gVarG = ((B) cVar2.b).b(query, this.m, this.n, this.o, searchFilters.a.a(), searchFilters.b.a(), searchFilters.c.a(), 1).g(new com.quizlet.remote.model.union.studysetwithcreator.a());
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        this.j = 1;
        Object objB = I1.b(gVarG, this);
        return objB == aVar ? aVar : objB;
    }
}
