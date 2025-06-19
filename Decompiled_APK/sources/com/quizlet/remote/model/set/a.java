package com.quizlet.remote.model.set;

import com.quizlet.generated.enums.EnumC4496k1;
import com.quizlet.generated.enums.EnumC4502m1;
import com.quizlet.generated.enums.K0;
import com.quizlet.remote.service.u;
import com.quizlet.remote.service.v;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public static final EnumC4502m1 c = EnumC4502m1.MERGED_USER_BASED_AND_ITEM_TO_ITEM;
    public static final EnumC4496k1 d = EnumC4496k1.SCHOOL_AND_COURSE_LEARNING_TO_RANK;
    public static final K0 e = K0.FREE;
    public final v a;
    public final u b;

    public a(v service, u coroutineService) {
        Intrinsics.checkNotNullParameter(service, "service");
        Intrinsics.checkNotNullParameter(coroutineService, "coroutineService");
        this.a = service;
        this.b = coroutineService;
    }
}
