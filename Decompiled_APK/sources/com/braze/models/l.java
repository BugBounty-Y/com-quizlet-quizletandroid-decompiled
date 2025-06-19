package com.braze.models;

import com.braze.support.DateTimeUtils;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l extends n {
    public l() {
        UUID uuidRandomUUID = UUID.randomUUID();
        Intrinsics.checkNotNullExpressionValue(uuidRandomUUID, "randomUUID(...)");
        o sessionId = new o(uuidRandomUUID);
        double dNowInSecondsPrecise = DateTimeUtils.nowInSecondsPrecise();
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        super(sessionId, dNowInSecondsPrecise, null, false);
    }

    @Override // com.braze.models.n
    public final Double d() {
        return this.c;
    }

    @Override // com.braze.models.n
    public final String toString() {
        return "\nMutableSession(sessionId=" + this.a + ", startTime=" + this.b + ", endTime=" + this.c + ", isSealed=" + this.d + ", duration=" + c() + ')';
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(o sessionId, double d, Double d2, boolean z) {
        super(sessionId, d, d2, z);
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
    }
}
