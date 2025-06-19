package com.quizlet.remote.model.course;

import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.Course;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements com.quizlet.remote.mapper.base.b {
    public static Course a(RemoteCourse remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        Long l = remote.f;
        return new Course(remote.d, j, l != null ? l.longValue() : 0L, remote.b, remote.c, remote.e);
    }

    public final List b(ApiThreeWrapper remoteCourseResponseList) {
        Intrinsics.checkNotNullParameter(remoteCourseResponseList, "remoteCourseResponseList");
        RemoteCourseResponse remoteCourseResponse = (RemoteCourseResponse) remoteCourseResponseList.a();
        return remoteCourseResponse == null ? K.a : T.f(this, remoteCourseResponse.d.a);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final /* bridge */ /* synthetic */ Object c(Object obj) {
        return a((RemoteCourse) obj);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final List e(List list) {
        return T.f(this, list);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public final Object h(Object obj) {
        Course data = (Course) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        long j = data.a;
        Long lValueOf = Long.valueOf(data.f);
        return new RemoteCourse(j, data.b, data.c, data.d, data.e, lValueOf);
    }
}
