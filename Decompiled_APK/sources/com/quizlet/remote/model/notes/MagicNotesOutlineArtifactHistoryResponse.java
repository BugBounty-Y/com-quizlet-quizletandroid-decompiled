package com.quizlet.remote.model.notes;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class MagicNotesOutlineArtifactHistoryResponse {
    public final boolean a;

    public MagicNotesOutlineArtifactHistoryResponse(@InterfaceC4853h(name = "user_edited") boolean z) {
        this.a = z;
    }

    @NotNull
    public final MagicNotesOutlineArtifactHistoryResponse copy(@InterfaceC4853h(name = "user_edited") boolean z) {
        return new MagicNotesOutlineArtifactHistoryResponse(z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof MagicNotesOutlineArtifactHistoryResponse) && this.a == ((MagicNotesOutlineArtifactHistoryResponse) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("MagicNotesOutlineArtifactHistoryResponse(userEdited="), this.a);
    }

    public /* synthetic */ MagicNotesOutlineArtifactHistoryResponse(boolean z, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? false : z);
    }
}
