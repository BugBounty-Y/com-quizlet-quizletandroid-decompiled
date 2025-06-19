package com.amazon.aps.shared.metrics.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class n {
    public final String a;

    public n(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        String str = this.a;
        if (str == null) {
            return 0;
        }
        return str.hashCode();
    }

    public final String toString() {
        return "ApsMetricsSdkInfo(version=" + ((Object) this.a) + ')';
    }
}
