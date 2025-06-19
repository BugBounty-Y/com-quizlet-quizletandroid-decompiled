package com.quizlet.remote.model.login;

import android.support.v4.media.session.a;
import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class EmailCheckResponse extends ApiResponse {
    public final List d;

    public EmailCheckResponse(@InterfaceC4853h(name = "responses") @NotNull List<ResponseData> data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.d = data;
    }

    @NotNull
    public final EmailCheckResponse copy(@InterfaceC4853h(name = "responses") @NotNull List<ResponseData> data) {
        Intrinsics.checkNotNullParameter(data, "data");
        return new EmailCheckResponse(data);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof EmailCheckResponse) && Intrinsics.b(this.d, ((EmailCheckResponse) obj).d);
    }

    public final int hashCode() {
        return this.d.hashCode();
    }

    public final String toString() {
        return a.n(")", new StringBuilder("EmailCheckResponse(data="), this.d);
    }
}
