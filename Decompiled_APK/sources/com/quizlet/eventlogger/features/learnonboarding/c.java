package com.quizlet.eventlogger.features.learnonboarding;

import androidx.compose.foundation.lazy.g;
import androidx.compose.foundation.lazy.o;
import androidx.compose.runtime.internal.d;
import com.quizlet.data.model.L1;
import com.quizlet.eventlogger.features.learnonboarding.LearnOnboardingEventLog;
import com.quizlet.eventlogger.model.AndroidEventLog;
import com.quizlet.features.achievements.ui.composables.z;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ Object c;

    public /* synthetic */ c(int i, long j, String str) {
        this.a = i;
        this.b = j;
        this.c = str;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                LearnOnboardingEventLog.Payload createEvent = (LearnOnboardingEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.setSetId(Long.valueOf(this.b));
                createEvent.setGoalOptions((String) this.c);
                break;
            case 1:
                AndroidEventLog logAndroidEvent = (AndroidEventLog) obj;
                Intrinsics.checkNotNullParameter(logAndroidEvent, "$this$logAndroidEvent");
                logAndroidEvent.getPayload().setFolderId(Long.valueOf(this.b));
                logAndroidEvent.getPayload().setTagName((String) this.c);
                break;
            default:
                g LazyColumn = (g) obj;
                Intrinsics.checkNotNullParameter(LazyColumn, "$this$LazyColumn");
                L1 l1 = (L1) this.c;
                LazyColumn.q(l1.a, null, o.c, new d(true, -732000046, new z(0, this.b)));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ c(L1 l1, long j) {
        this.a = 2;
        this.c = l1;
        this.b = j;
    }
}
