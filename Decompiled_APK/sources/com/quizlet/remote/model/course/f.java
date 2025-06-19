package com.quizlet.remote.model.course;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.n;
import com.quizlet.remote.model.base.ApiPostBody;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ long k;
    public final /* synthetic */ long l;
    public final /* synthetic */ n m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(long j, long j2, n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
        this.l = j2;
        this.m = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
        RemoteDeleteCourseMembership remoteDeleteCourseMembership = new RemoteDeleteCourseMembership(this.k, this.l);
        com.quizlet.remote.service.i iVar = (com.quizlet.remote.service.i) this.m.a;
        ApiPostBody<RemoteDeleteCourseMembership> apiPostBody = new ApiPostBody<>(A.b(remoteDeleteCourseMembership));
        this.j = 1;
        Object objB = iVar.b(apiPostBody, this);
        return objB == aVar ? aVar : objB;
    }
}
