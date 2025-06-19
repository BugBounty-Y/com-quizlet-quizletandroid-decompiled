package com.snowplowanalytics.core.session;

import android.app.Activity;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public synchronized c a(Activity context, long j, long j2, TimeUnit timeUnit, Runnable[] runnableArr, boolean z) {
        c cVar;
        try {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(timeUnit, "timeUnit");
            cVar = new c(j, j2, timeUnit, context, z);
            Runnable[] runnableArr2 = {null, null, null, null};
            if (runnableArr != null && runnableArr.length == 4) {
                runnableArr2 = runnableArr;
            }
            cVar.k = runnableArr2[0];
            cVar.l = runnableArr2[1];
            cVar.m = runnableArr2[2];
            cVar.n = runnableArr2[3];
        } catch (Throwable th) {
            throw th;
        }
        return cVar;
    }
}
