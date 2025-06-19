package com.quizlet.quizletandroid.ui.activitycenter.models;

import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.User;
import com.quizlet.data.model.W0;
import com.quizlet.features.match.data.J;
import com.quizlet.features.match.data.K;
import com.quizlet.features.match.data.L;
import com.quizlet.features.match.data.Q;
import com.quizlet.remote.model.practicetests.PracticeTestSummaryResponse;
import com.quizlet.remote.model.practicetests.RemoteQuestionBankResultsResponse;
import com.quizlet.remote.model.user.RemoteUser;
import io.reactivex.rxjava3.functions.h;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements h, com.quizlet.mapper.a, com.quizlet.remote.mapper.base.b {
    public static User b(RemoteUser remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        String str = remote.b;
        String str2 = str == null ? "" : str;
        Long l = remote.c;
        long jLongValue = l != null ? l.longValue() : 0L;
        Long l2 = remote.d;
        long jLongValue2 = l2 != null ? l2.longValue() : 0L;
        Integer num = remote.f;
        int iIntValue = num != null ? num.intValue() : 0;
        Integer num2 = remote.g;
        int iIntValue2 = num2 != null ? num2.intValue() : 0;
        Boolean bool = remote.h;
        boolean zBooleanValue = bool != null ? bool.booleanValue() : true;
        String str3 = remote.i;
        String str4 = str3 == null ? "" : str3;
        Boolean bool2 = remote.e;
        return new User(j, str2, jLongValue, jLongValue2, bool2 != null ? bool2.booleanValue() : false, iIntValue, iIntValue2, zBooleanValue, str4, remote.j, remote.k, remote.l, remote.m, remote.n, remote.o);
    }

    public static RemoteUser d(User data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return new RemoteUser(data.a, data.b, Long.valueOf(data.c), Long.valueOf(data.d), Boolean.valueOf(data.e), Integer.valueOf(data.f), Integer.valueOf(data.g), Boolean.valueOf(data.h), data.i, data.j, data.k, data.l, data.m, data.n, null, 16384, null);
    }

    @Override // com.quizlet.mapper.a
    public Object a(Object obj) {
        RemoteQuestionBankResultsResponse input = (RemoteQuestionBankResultsResponse) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        ArrayList arrayList = new ArrayList();
        for (PracticeTestSummaryResponse practiceTestSummaryResponse : input.d.a) {
            arrayList.add(new W0(practiceTestSummaryResponse.a, practiceTestSummaryResponse.b, practiceTestSummaryResponse.c, practiceTestSummaryResponse.d, practiceTestSummaryResponse.e));
        }
        return arrayList;
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Q p0 = (Q) obj;
        Intrinsics.checkNotNullParameter(p0, "p0");
        int i = p0.b;
        return i == 0 ? K.a : p0.a.a ? new L(i) : new J(i);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public /* bridge */ /* synthetic */ Object c(Object obj) {
        return b((RemoteUser) obj);
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return T.f(this, list);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public /* bridge */ /* synthetic */ Object h(Object obj) {
        return d((User) obj);
    }
}
