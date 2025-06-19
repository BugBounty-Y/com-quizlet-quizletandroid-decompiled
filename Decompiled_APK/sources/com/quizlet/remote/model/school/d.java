package com.quizlet.remote.model.school;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.school.memberships.RemoteDeleteSchoolMembership;
import com.quizlet.remote.service.x;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ long k;
    public final /* synthetic */ long l;
    public final /* synthetic */ com.quizlet.data.repository.set.f m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(long j, long j2, com.quizlet.data.repository.set.f fVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
        this.l = j2;
        this.m = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
        ApiPostBody<RemoteDeleteSchoolMembership> apiPostBody = new ApiPostBody<>(A.b(new RemoteDeleteSchoolMembership(this.k, this.l)));
        x xVar = (x) this.m.b;
        this.j = 1;
        Object objD = xVar.d(apiPostBody, this);
        return objD == aVar ? aVar : objD;
    }
}
