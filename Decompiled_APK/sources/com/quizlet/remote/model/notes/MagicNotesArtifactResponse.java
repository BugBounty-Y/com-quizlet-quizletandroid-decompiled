package com.quizlet.remote.model.notes;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class MagicNotesArtifactResponse {
    public final String a;
    public final String b;
    public final long c;
    public final String d;
    public final String e;
    public final int f;
    public final String g;

    public MagicNotesArtifactResponse(String uuid, String noteUuid, long j, String content, String type, int i, String str) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(noteUuid, "noteUuid");
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = uuid;
        this.b = noteUuid;
        this.c = j;
        this.d = content;
        this.e = type;
        this.f = i;
        this.g = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof MagicNotesArtifactResponse)) {
            return false;
        }
        MagicNotesArtifactResponse magicNotesArtifactResponse = (MagicNotesArtifactResponse) obj;
        return Intrinsics.b(this.a, magicNotesArtifactResponse.a) && Intrinsics.b(this.b, magicNotesArtifactResponse.b) && this.c == magicNotesArtifactResponse.c && Intrinsics.b(this.d, magicNotesArtifactResponse.d) && Intrinsics.b(this.e, magicNotesArtifactResponse.e) && this.f == magicNotesArtifactResponse.f && Intrinsics.b(this.g, magicNotesArtifactResponse.g);
    }

    public final int hashCode() {
        int iB = d0.b(this.f, d0.e(d0.e(d0.d(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31);
        String str = this.g;
        return iB + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MagicNotesArtifactResponse(uuid=");
        sb.append(this.a);
        sb.append(", noteUuid=");
        sb.append(this.b);
        sb.append(", userId=");
        sb.append(this.c);
        sb.append(", content=");
        sb.append(this.d);
        sb.append(", type=");
        sb.append(this.e);
        sb.append(", status=");
        sb.append(this.f);
        sb.append(", history=");
        return android.support.v4.media.session.a.t(sb, this.g, ")");
    }

    public /* synthetic */ MagicNotesArtifactResponse(String str, String str2, long j, String str3, String str4, int i, String str5, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(str, str2, j, str3, str4, i, (i2 & 64) != 0 ? null : str5);
    }
}
