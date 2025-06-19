package com.braze.managers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.braze.managers.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1503p extends BroadcastReceiver {
    public final /* synthetic */ r a;

    public C1503p(r rVar) {
        this.a = rVar;
    }

    public static final String a() {
        return "Session seal logic executing in broadcast";
    }

    @Override // android.content.BroadcastReceiver
    public final void onReceive(Context context, Intent intent) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(intent, "intent");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new K(27), 6, (Object) null);
        kotlinx.coroutines.E.A(BrazeCoroutineScope.INSTANCE, null, null, new C1502o(this.a, goAsync(), null), 3);
    }
}
