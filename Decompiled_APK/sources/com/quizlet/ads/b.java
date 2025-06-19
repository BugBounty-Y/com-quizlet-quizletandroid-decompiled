package com.quizlet.ads;

import com.quizlet.generated.enums.J;
import io.reactivex.rxjava3.core.p;
import java.util.Calendar;
import java.util.List;
import kotlin.collections.B;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public static final List d = B.j(J.PORTUGUESE, J.FRENCH, J.CHINESE);
    public final androidx.work.impl.model.c a;
    public final d b;
    public final com.quizlet.data.repository.user.a c;

    public b(androidx.work.impl.model.c userProperties, d adUnitSessionTracker, com.quizlet.data.repository.user.a isPrebidEnabledFeature) {
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(adUnitSessionTracker, "adUnitSessionTracker");
        Intrinsics.checkNotNullParameter(isPrebidEnabledFeature, "isPrebidEnabledFeature");
        this.a = userProperties;
        this.b = adUnitSessionTracker;
        this.c = isPrebidEnabledFeature;
    }

    public final p a() {
        Calendar today = Calendar.getInstance();
        Intrinsics.checkNotNullExpressionValue(today, "getInstance(...)");
        androidx.work.impl.model.c cVar = this.a;
        Intrinsics.checkNotNullParameter(today, "today");
        p pVarQ = p.q(new com.quizlet.local.ormlite.models.term.b(new com.quizlet.data.repository.school.membership.a(this, 28), 19), cVar.o(new com.quizlet.features.setpage.header.ui.g(10, cVar, today), 0), cVar.y(), cVar.r(), cVar.q(), this.c.w());
        Intrinsics.checkNotNullExpressionValue(pVarQ, "zip(...)");
        return pVarQ;
    }
}
