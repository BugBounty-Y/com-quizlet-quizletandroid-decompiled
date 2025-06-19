package com.quizlet.eventlogger.features.achievements;

import com.quizlet.eventlogger.features.achievements.AchievementsToastInteractionEventLog;
import com.quizlet.eventlogger.features.autolaunch.AutoLaunchEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class a implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ String b;
    public final /* synthetic */ int c;

    public /* synthetic */ a(String str, int i, int i2) {
        this.a = i2;
        this.b = str;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                AchievementsToastInteractionEventLog.Payload createEvent = (AchievementsToastInteractionEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent, "$this$createEvent");
                createEvent.c(Integer.valueOf(this.c), this.b);
                break;
            default:
                AutoLaunchEventLog.Payload createEvent2 = (AutoLaunchEventLog.Payload) obj;
                Intrinsics.checkNotNullParameter(createEvent2, "$this$createEvent");
                createEvent2.setReason(this.b);
                createEvent2.setSecondsPassed(Integer.valueOf(this.c));
                break;
        }
        return Unit.a;
    }
}
