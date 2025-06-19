package com.quizlet.data.model.ads;

import com.quizlet.openwrap.OpenWrapException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d implements f {
    public final OpenWrapException a;

    public d(OpenWrapException error) {
        Intrinsics.checkNotNullParameter(error, "error");
        this.a = error;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && this.a.equals(((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Failure(error=" + this.a + ")";
    }
}
