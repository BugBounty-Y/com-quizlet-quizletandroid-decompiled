package com.quizlet.remote.model.notes;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class MagicNotesTitleArtifactResponse {
    public final String a;

    public MagicNotesTitleArtifactResponse(String str) {
        this.a = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof MagicNotesTitleArtifactResponse) && Intrinsics.b(this.a, ((MagicNotesTitleArtifactResponse) obj).a);
    }

    public final int hashCode() {
        String str = this.a;
        if (str == null) {
            return 0;
        }
        return str.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("MagicNotesTitleArtifactResponse(title="), this.a, ")");
    }

    public /* synthetic */ MagicNotesTitleArtifactResponse(String str, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : str);
    }
}
