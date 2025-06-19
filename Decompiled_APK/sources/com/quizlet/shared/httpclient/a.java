package com.quizlet.shared.httpclient;

import com.quizlet.shared.httpclient.exceptions.NetworkErrorException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final NetworkErrorException a;

    public a(NetworkErrorException cause) {
        Intrinsics.checkNotNullParameter(cause, "cause");
        this.a = cause;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && this.a.equals(((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Failure(cause=" + this.a + ")";
    }
}
