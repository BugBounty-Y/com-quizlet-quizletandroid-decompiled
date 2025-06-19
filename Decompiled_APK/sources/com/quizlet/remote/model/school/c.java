package com.quizlet.remote.model.school;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.service.x;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ String k;
    public final /* synthetic */ String l;
    public final /* synthetic */ String m;
    public final /* synthetic */ String n;
    public final /* synthetic */ com.quizlet.data.repository.set.f o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(String str, String str2, String str3, String str4, com.quizlet.data.repository.set.f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = str2;
        this.m = str3;
        this.n = str4;
        this.o = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.data.repository.set.f fVar = this.o;
        if (i == 0) {
            Z.e(obj);
            ApiPostBody<RemoteNewSchool> apiPostBody = new ApiPostBody<>(A.b(new RemoteNewSchool(this.k, this.l, this.m, this.n)));
            x xVar = (x) fVar.b;
            this.j = 1;
            obj = xVar.e(apiPostBody, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return CollectionsKt.L(((a) fVar.c).b((ApiThreeWrapper) obj));
    }
}
