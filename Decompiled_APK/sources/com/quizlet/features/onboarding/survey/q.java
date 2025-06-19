package com.quizlet.features.onboarding.survey;

import androidx.collection.Y;
import androidx.lifecycle.w0;
import com.quizlet.local.datastore.preferences.n0;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.collections.A;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class q extends w0 {
    public final long b;
    public final n0 c;
    public final k d;
    public final s0 e;
    public final d0 f;

    public q(long j, n0 onboardingSurveyPreferences, k onboardingSurveyLogger) {
        Intrinsics.checkNotNullParameter(onboardingSurveyPreferences, "onboardingSurveyPreferences");
        Intrinsics.checkNotNullParameter(onboardingSurveyLogger, "onboardingSurveyLogger");
        this.b = j;
        this.c = onboardingSurveyPreferences;
        this.d = onboardingSurveyLogger;
        this.f = e0.b(0, 0, null, 7);
        kotlin.enums.b bVar = m.e;
        ArrayList arrayList = new ArrayList();
        bVar.getClass();
        Y y = new Y(bVar, 5);
        while (y.hasNext()) {
            Object next = y.next();
            m mVar = (m) next;
            if (mVar != m.b && mVar != m.c) {
                arrayList.add(next);
            }
        }
        this.e = e0.c(new n(CollectionsKt.d0(A.c(arrayList), m.c), m.b));
    }
}
