package com.braze.models;

import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o implements IPutIntoJson {
    public final UUID a;
    public final String b;

    public o(UUID sessionIdUuid) {
        Intrinsics.checkNotNullParameter(sessionIdUuid, "sessionIdUuid");
        this.a = sessionIdUuid;
        String string = sessionIdUuid.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        this.b = string;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof o) && Intrinsics.b(this.a, ((o) obj).a);
    }

    @Override // com.braze.models.IPutIntoJson
    public final Object forJsonPut() {
        return this.b;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return this.b;
    }
}
