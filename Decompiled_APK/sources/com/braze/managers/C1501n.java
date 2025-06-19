package com.braze.managers;

import android.content.Context;
import android.content.SharedPreferences;
import com.braze.support.BrazeLogger;
import com.braze.support.DateTimeUtils;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.braze.managers.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1501n {
    public final com.braze.events.d a;
    public final com.braze.storage.e0 b;
    public final SharedPreferences c;
    public boolean d;

    public C1501n(Context applicationContext, com.braze.events.d eventPublisher, com.braze.storage.e0 serverConfigStorageProvider) {
        Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
        Intrinsics.checkNotNullParameter(eventPublisher, "eventPublisher");
        Intrinsics.checkNotNullParameter(serverConfigStorageProvider, "serverConfigStorageProvider");
        this.a = eventPublisher;
        this.b = serverConfigStorageProvider;
        this.c = applicationContext.getSharedPreferences("com.appboy.storage.sessions.messaging_session", 0);
    }

    public static final String c() {
        return "Publishing new messaging session event.";
    }

    public static final String d() {
        return "Messaging session not started.";
    }

    public final boolean a() {
        long jR = this.b.r();
        if (jR == -1 || this.d) {
            return false;
        }
        long j = this.c.getLong("messaging_session_timestamp", -1L);
        long jNowInSeconds = DateTimeUtils.nowInSeconds();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new N(jR, jNowInSeconds, 0, j), 7, (Object) null);
        return jR + j < jNowInSeconds;
    }

    public final void b() {
        if (!a()) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new K(23), 7, (Object) null);
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new K(22), 7, (Object) null);
        this.a.b(com.braze.events.internal.n.a, com.braze.events.internal.n.class);
        this.d = true;
    }

    public final void e() {
        long jNowInSeconds = DateTimeUtils.nowInSeconds();
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.dispatch.j(6, jNowInSeconds), 7, (Object) null);
        this.c.edit().putLong("messaging_session_timestamp", jNowInSeconds).apply();
        this.d = false;
    }

    public static final String a(long j, long j2, long j3) {
        StringBuilder sbT = androidx.compose.animation.d0.t(j, "Messaging session timeout: ", ", current diff: ");
        sbT.append(j2 - j3);
        return sbT.toString();
    }

    public static final String a(long j) {
        return androidx.compose.animation.d0.n(j, "Messaging session stopped. Adding new messaging session timestamp: ");
    }
}
