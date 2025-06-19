package com.braze.analytics;

import com.braze.AbstractC1484j;
import com.braze.W;
import com.braze.models.i;
import com.braze.support.BrazeLogger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class b implements c {
    public static final String e(String str) {
        return AbstractC1484j.a("Cannot create card control event for Feed card. Returning null. Card id: ", str);
    }

    public static final String f(String str) {
        return AbstractC1484j.a("Cannot create card dismissed event for Feed card. Returning null. Card id: ", str);
    }

    @Override // com.braze.analytics.c
    public final i a(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new W(cardId, 8), 6, (Object) null);
        return null;
    }

    @Override // com.braze.analytics.c
    public final i b(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return com.braze.models.outgoing.event.b.g.k(cardId);
    }

    @Override // com.braze.analytics.c
    public final i c(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new W(cardId, 7), 6, (Object) null);
        return null;
    }

    @Override // com.braze.analytics.c
    public final i d(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return com.braze.models.outgoing.event.b.g.m(cardId);
    }
}
