package com.quizlet.remote.model.term;

import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class TermResponse extends ApiResponse {
    public final TermModels d;

    public TermResponse(@InterfaceC4853h(name = "models") TermModels termModels) {
        this.d = termModels;
    }

    @NotNull
    public final TermResponse copy(@InterfaceC4853h(name = "models") TermModels termModels) {
        return new TermResponse(termModels);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof TermResponse) && Intrinsics.b(this.d, ((TermResponse) obj).d);
    }

    public final int hashCode() {
        TermModels termModels = this.d;
        if (termModels == null) {
            return 0;
        }
        return termModels.a.hashCode();
    }

    public final String toString() {
        return "TermResponse(models=" + this.d + ")";
    }
}
