package com.braze.triggers.managers;

import androidx.compose.animation.d0;
import com.braze.E;
import com.braze.managers.N;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class c {
    public static boolean a(com.braze.triggers.events.b triggerEvent, com.braze.triggers.actions.g action, long j, long j2) {
        long j3;
        Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
        Intrinsics.checkNotNullParameter(action, "action");
        if (triggerEvent instanceof com.braze.triggers.events.h) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, f.q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new i(1), 14, (Object) null);
            return true;
        }
        long jNowInSeconds = DateTimeUtils.nowInSeconds();
        long j4 = jNowInSeconds + r0.d;
        int i = action.b.g;
        if (i != -1) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, f.q, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.enums.i(i, 17), 14, (Object) null);
            j3 = j + i;
        } else {
            j3 = j + j2;
        }
        long j5 = j3;
        if (j4 >= j5) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, f.q, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new E(j4, j5, 1), 12, (Object) null);
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, f.q, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new N(j2, j5, 1, j4), 12, (Object) null);
        return false;
    }

    public static final String a() {
        return "Ignoring minimum time interval between triggered actions because the trigger event is a test.";
    }

    public static final String a(int i) {
        return android.support.v4.media.session.a.f(i, "Using override minimum display interval: ");
    }

    public static final String a(long j, long j2) {
        StringBuilder sbT = d0.t(j, "Minimum time interval requirement met for matched trigger. Action display time: ", " . Next viable display time: ");
        sbT.append(j2);
        return sbT.toString();
    }

    public static final String a(long j, long j2, long j3) {
        StringBuilder sbT = d0.t(j, "Minimum time interval requirement and triggered action override time interval requirement of ", " not met for matched trigger. Returning null. Next viable display time: ");
        sbT.append(j2);
        sbT.append(". Action display time: ");
        sbT.append(j3);
        return sbT.toString();
    }
}
