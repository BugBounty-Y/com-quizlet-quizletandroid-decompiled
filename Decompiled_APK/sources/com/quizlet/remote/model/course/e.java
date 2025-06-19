package com.quizlet.remote.model.course;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.n;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.course.RemoteNewCourseMembershipResponse;
import java.util.List;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ long k;
    public final /* synthetic */ long l;
    public final /* synthetic */ long m;
    public final /* synthetic */ String n;
    public final /* synthetic */ n o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(long j, long j2, long j3, String str, n nVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
        this.l = j2;
        this.m = j3;
        this.n = str;
        this.o = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        List list;
        RemoteNewCourseMembershipResponse.CourseMembershipModelsResponse courseMembershipModelsResponse;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        n nVar = this.o;
        if (i == 0) {
            Z.e(obj);
            RemoteNewCourseMembership remoteNewCourseMembership = new RemoteNewCourseMembership(this.k, new Long(this.l), this.m, this.n);
            com.quizlet.remote.service.i iVar = (com.quizlet.remote.service.i) nVar.a;
            ApiPostBody<RemoteNewCourseMembership> apiPostBody = new ApiPostBody<>(A.b(remoteNewCourseMembership));
            this.j = 1;
            obj = iVar.a(apiPostBody, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        com.quizlet.quizletandroid.ui.folder.logging.a aVar2 = (com.quizlet.quizletandroid.ui.folder.logging.a) nVar.c;
        RemoteNewCourseMembershipResponse remoteNewCourseMembershipResponse = (RemoteNewCourseMembershipResponse) ((ApiThreeWrapper) obj).a();
        if (remoteNewCourseMembershipResponse == null || (courseMembershipModelsResponse = remoteNewCourseMembershipResponse.d) == null || (list = courseMembershipModelsResponse.b) == null) {
            list = K.a;
        }
        return CollectionsKt.firstOrNull(T.f(aVar2, list));
    }
}
