package com.braze.analytics;

import com.braze.models.i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a implements c {
    @Override // com.braze.analytics.c
    public final i a(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return com.braze.models.outgoing.event.b.g.g(cardId);
    }

    @Override // com.braze.analytics.c
    public final i b(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return com.braze.models.outgoing.event.b.g.c(cardId);
    }

    @Override // com.braze.analytics.c
    public final i c(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return com.braze.models.outgoing.event.b.g.e(cardId);
    }

    @Override // com.braze.analytics.c
    public final i d(String cardId) {
        Intrinsics.checkNotNullParameter(cardId, "cardId");
        return com.braze.models.outgoing.event.b.g.i(cardId);
    }
}
