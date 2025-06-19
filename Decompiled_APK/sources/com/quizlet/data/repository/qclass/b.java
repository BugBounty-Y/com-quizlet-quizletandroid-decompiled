package com.quizlet.data.repository.qclass;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.google.firebase.messaging.u;
import com.quizlet.login.common.interactors.d;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.qclass.ClassResponse;
import com.quizlet.remote.service.InterfaceC4778e;
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
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;
    public final /* synthetic */ Integer n;
    public final /* synthetic */ int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, String str, String str2, Integer num, int i, h hVar) {
        super(2, hVar);
        this.k = cVar;
        this.l = str;
        this.m = str2;
        this.n = num;
        this.o = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, this.m, this.n, this.o, hVar);
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
        u uVar = (u) this.k.b;
        String query = this.l;
        Intrinsics.checkNotNullParameter(query, "query");
        d dVar = (d) uVar.a;
        Intrinsics.checkNotNullParameter(query, "query");
        p<K<ApiThreeWrapper<ClassResponse>>> pVarA = ((InterfaceC4778e) dVar.b).a(query, this.m, this.n, this.o);
        Intrinsics.checkNotNullParameter(pVarA, "<this>");
        com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a classMapper = (com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a) uVar.b;
        Intrinsics.checkNotNullParameter(classMapper, "classMapper");
        com.quizlet.remote.model.school.a schoolMapper = (com.quizlet.remote.model.school.a) uVar.c;
        Intrinsics.checkNotNullParameter(schoolMapper, "schoolMapper");
        com.quizlet.quizletandroid.ui.folder.logging.a pagingMapper = (com.quizlet.quizletandroid.ui.folder.logging.a) uVar.d;
        Intrinsics.checkNotNullParameter(pagingMapper, "pagingMapper");
        g gVarG = pVarA.g(new com.quizlet.quizletandroid.ui.common.adapter.c());
        Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
        this.j = 1;
        Object objB = I1.b(gVarG, this);
        return objB == aVar ? aVar : objB;
    }
}
