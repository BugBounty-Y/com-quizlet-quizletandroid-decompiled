package com.quizlet.login.authentication.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends i {
    public final String a;

    public b(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        String str = this.a;
        if (str == null) {
            return 0;
        }
        return str.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("ApiThreeError(errorMessage="), this.a, ")");
    }
}
