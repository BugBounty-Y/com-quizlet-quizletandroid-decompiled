package com.braze.events.internal;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class l {
    public final List a;

    public l(List geofencesList) {
        Intrinsics.checkNotNullParameter(geofencesList, "geofencesList");
        this.a = geofencesList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof l) && Intrinsics.b(this.a, ((l) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "GeofencesReceivedEvent(geofencesList=" + this.a + ')';
    }
}
