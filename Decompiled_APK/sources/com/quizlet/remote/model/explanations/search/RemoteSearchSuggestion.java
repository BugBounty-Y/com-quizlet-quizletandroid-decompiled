package com.quizlet.remote.model.explanations.search;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteSearchSuggestion {
    public final String a;
    public final int b;

    public RemoteSearchSuggestion(String suggestion, int i) {
        Intrinsics.checkNotNullParameter(suggestion, "suggestion");
        this.a = suggestion;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteSearchSuggestion)) {
            return false;
        }
        RemoteSearchSuggestion remoteSearchSuggestion = (RemoteSearchSuggestion) obj;
        return Intrinsics.b(this.a, remoteSearchSuggestion.a) && this.b == remoteSearchSuggestion.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "RemoteSearchSuggestion(suggestion=" + this.a + ", rank=" + this.b + ")";
    }
}
