package com.quizlet.remote.model.notes;

import androidx.compose.animation.d0;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class MagicNotesResponse {
    public final String a;
    public final long b;
    public final List c;
    public final boolean d;
    public final String e;
    public final String f;

    public MagicNotesResponse(@NotNull String uuid, long j, @NotNull List<String> artifactUuids, @InterfaceC4853h(name = "private") boolean z, @NotNull String extractedText, @NotNull String createdAt) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(artifactUuids, "artifactUuids");
        Intrinsics.checkNotNullParameter(extractedText, "extractedText");
        Intrinsics.checkNotNullParameter(createdAt, "createdAt");
        this.a = uuid;
        this.b = j;
        this.c = artifactUuids;
        this.d = z;
        this.e = extractedText;
        this.f = createdAt;
    }

    @NotNull
    public final MagicNotesResponse copy(@NotNull String uuid, long j, @NotNull List<String> artifactUuids, @InterfaceC4853h(name = "private") boolean z, @NotNull String extractedText, @NotNull String createdAt) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(artifactUuids, "artifactUuids");
        Intrinsics.checkNotNullParameter(extractedText, "extractedText");
        Intrinsics.checkNotNullParameter(createdAt, "createdAt");
        return new MagicNotesResponse(uuid, j, artifactUuids, z, extractedText, createdAt);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MagicNotesResponse)) {
            return false;
        }
        MagicNotesResponse magicNotesResponse = (MagicNotesResponse) obj;
        return Intrinsics.b(this.a, magicNotesResponse.a) && this.b == magicNotesResponse.b && Intrinsics.b(this.c, magicNotesResponse.c) && this.d == magicNotesResponse.d && Intrinsics.b(this.e, magicNotesResponse.e) && Intrinsics.b(this.f, magicNotesResponse.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + d0.e(d0.g(d0.f(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MagicNotesResponse(uuid=");
        sb.append(this.a);
        sb.append(", userId=");
        sb.append(this.b);
        sb.append(", artifactUuids=");
        sb.append(this.c);
        sb.append(", isPrivate=");
        sb.append(this.d);
        sb.append(", extractedText=");
        sb.append(this.e);
        sb.append(", createdAt=");
        return android.support.v4.media.session.a.t(sb, this.f, ")");
    }
}
