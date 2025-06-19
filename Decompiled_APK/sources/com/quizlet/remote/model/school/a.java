package com.quizlet.remote.model.school;

import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.School;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.collections.C;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.remote.mapper.base.b {
    public static School a(RemoteSchool remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        return new School(remote.a, remote.b, remote.c, remote.d, remote.e, remote.f, remote.g, remote.h, remote.i, remote.j);
    }

    public final List b(ApiThreeWrapper remoteSchoolResponseList) {
        Intrinsics.checkNotNullParameter(remoteSchoolResponseList, "remoteSchoolResponseList");
        RemoteSchoolResponse remoteSchoolResponse = (RemoteSchoolResponse) remoteSchoolResponseList.a();
        if (remoteSchoolResponse == null) {
            return K.a;
        }
        List list = remoteSchoolResponse.d.a;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(a((RemoteSchool) it2.next()));
        }
        return arrayList;
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final /* bridge */ /* synthetic */ Object c(Object obj) {
        return a((RemoteSchool) obj);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public final List e(List list) {
        return T.f(this, list);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public final Object h(Object obj) {
        School data = (School) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        return new RemoteSchool(data.a, data.b, data.c, data.d, data.e, data.f, data.g, data.h, data.i, data.j);
    }
}
