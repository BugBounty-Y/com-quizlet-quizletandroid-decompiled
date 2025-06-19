package com.braze.events.internal;

import com.braze.managers.o0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class t {
    public final o0 a;

    public t(o0 debugConfig) {
        Intrinsics.checkNotNullParameter(debugConfig, "debugConfig");
        this.a = debugConfig;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof t) && Intrinsics.b(this.a, ((t) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SdkDebuggerConfigUpdateEvent(debugConfig=" + this.a + ')';
    }
}
