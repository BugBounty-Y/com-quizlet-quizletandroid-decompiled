package com.quizlet.api.okhttp.interceptors;

import com.quizlet.infra.contracts.session.a;
import java.util.Date;
import java.util.UUID;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class AppSessionIdProvider implements a {
    public UUID a;
    public Date b;

    public static /* synthetic */ void getSCurrentAppSessionId$annotations() {
    }

    public static /* synthetic */ void getSLastAction$annotations() {
    }

    public final UUID a() {
        if (this.a == null || assistantMode.refactored.a.f() - this.b.getTime() > 1800000) {
            this.a = UUID.randomUUID();
            this.b = new Date();
        }
        UUID uuid = this.a;
        Intrinsics.d(uuid);
        return uuid;
    }
}
