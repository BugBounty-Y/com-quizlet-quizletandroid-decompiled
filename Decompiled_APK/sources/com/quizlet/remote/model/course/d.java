package com.quizlet.remote.model.course;

import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.model.n;
import com.quizlet.data.model.Course;
import com.quizlet.data.repository.course.exceptions.CreateDuplicatedCourseException;
import com.quizlet.data.repository.course.exceptions.CreateNewCourseException;
import com.quizlet.remote.model.base.ApiPostBody;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import retrofit2.HttpException;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ String k;
    public final /* synthetic */ String l;
    public final /* synthetic */ n m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(n nVar, String str, String str2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = str2;
        this.m = nVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.m, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws CreateNewCourseException, CreateDuplicatedCourseException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        n nVar = this.m;
        String str = this.l;
        String str2 = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                ApiPostBody<RemoteNewCourse> apiPostBody = new ApiPostBody<>(A.b(new RemoteNewCourse(str2, str)));
                com.quizlet.remote.service.i iVar = (com.quizlet.remote.service.i) nVar.a;
                this.j = 1;
                obj = iVar.e(apiPostBody, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return (Course) CollectionsKt.L(((c) nVar.b).b((ApiThreeWrapper) obj));
        } catch (Exception e) {
            if ((e instanceof HttpException) && ((HttpException) e).a == 409) {
                throw new CreateDuplicatedCourseException(str2, str);
            }
            throw new CreateNewCourseException();
        }
    }
}
