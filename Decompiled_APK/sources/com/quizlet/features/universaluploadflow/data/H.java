package com.quizlet.features.universaluploadflow.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class H implements K {
    public final InterfaceC4456e a;

    public H(InterfaceC4456e reason) {
        Intrinsics.checkNotNullParameter(reason, "reason");
        this.a = reason;
    }

    @Override // com.quizlet.features.universaluploadflow.data.K
    public final boolean a() {
        return false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof H) && Intrinsics.b(this.a, ((H) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Error(reason=" + this.a + ")";
    }
}
