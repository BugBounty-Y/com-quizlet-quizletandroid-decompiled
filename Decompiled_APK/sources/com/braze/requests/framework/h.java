package com.braze.requests.framework;

import com.braze.H;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;

/* loaded from: classes.dex */
public final class h {
    public final com.braze.requests.n a;
    public long b;
    public final long c;
    public i d;
    public int e;
    public Integer f;
    public long g;
    public int h;

    public h(com.braze.requests.n request, long j, long j2) {
        i state = i.a;
        Intrinsics.checkNotNullParameter(request, "request");
        Intrinsics.checkNotNullParameter(state, "state");
        this.a = request;
        this.b = j;
        this.c = j2;
        this.d = state;
        this.e = 0;
        this.f = null;
        this.g = j2;
    }

    public final void a(long j, i newState) {
        Intrinsics.checkNotNullParameter(newState, "newState");
        if (this.d != newState) {
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.Priority priority = BrazeLogger.Priority.V;
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, true, (Function0) new H(this, newState, j, 3), 2, (Object) null);
            this.g = j;
            this.d = newState;
            if (newState == i.b) {
                this.h++;
                BrazeLogger.brazelog$default(brazeLogger, (Object) this, priority, (Throwable) null, true, (Function0) new l(this, j, 3), 2, (Object) null);
            }
        }
    }

    public static final String a(h hVar, i iVar, long j) {
        return "Moving from " + hVar.d + " -> " + iVar + " with time " + j + " for \n" + hVar.a(j);
    }

    public static final String a(h hVar, long j) {
        return "Moving to pending retry.Updated retry count: " + hVar.h + " for: \n" + hVar.a(j);
    }

    public final String a(long j) {
        return x.d("\n            |RequestInfo for " + this.a.hashCode() + " \n            | at " + j + "\n            | request.target = " + ((com.braze.requests.b) this.a).e() + "\n            | nextAdvance = " + (this.b - j) + "\n            | createdAt = " + (this.c - j) + "\n            | state = " + this.d + "\n            | lastStateMovedAt = " + (this.g - j) + "\n            | timesMovedToRetry = " + this.h + "\n        ");
    }
}
