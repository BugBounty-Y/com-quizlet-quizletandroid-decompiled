package com.quizlet.remote.model.login;

import android.support.v4.media.session.a;
import com.squareup.moshi.m;
import java.io.Serializable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class ValidateEmailRequest implements Serializable {
    public final String a;

    public ValidateEmailRequest(String email) {
        Intrinsics.checkNotNullParameter(email, "email");
        this.a = email;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof ValidateEmailRequest) && Intrinsics.b(this.a, ((ValidateEmailRequest) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return a.t(new StringBuilder("ValidateEmailRequest(email="), this.a, ")");
    }
}
