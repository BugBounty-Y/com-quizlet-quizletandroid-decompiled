package com.quizlet.login.recovery.forgotpassword.data;

import com.quizlet.api.model.ApiThreeWrapper;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements c {
    public final ApiThreeWrapper a;
    public final Throwable b;

    public b(ApiThreeWrapper apiThreeWrapper, Throwable th, int i) {
        apiThreeWrapper = (i & 1) != 0 ? null : apiThreeWrapper;
        th = (i & 2) != 0 ? null : th;
        this.a = apiThreeWrapper;
        this.b = th;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        ApiThreeWrapper apiThreeWrapper = this.a;
        int iHashCode = (apiThreeWrapper == null ? 0 : apiThreeWrapper.hashCode()) * 31;
        Throwable th = this.b;
        return iHashCode + (th != null ? th.hashCode() : 0);
    }

    public final String toString() {
        return "Response(data=" + this.a + ", error=" + this.b + ")";
    }
}
