package com.braze.events.internal;

import kotlin.jvm.internal.Intrinsics;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class a {
    public final JSONObject a;

    public a(JSONObject bannersData) {
        Intrinsics.checkNotNullParameter(bannersData, "bannersData");
        this.a = bannersData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "BannersReceivedEvent(bannersData=" + this.a + ')';
    }
}
