package com.quizlet.shared.models.api.notes;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class StudyNotesArtifactsResponse {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final String b;
    public final long c;
    public final String d;
    public final com.quizlet.shared.enums.studynotes.d e;
    public final String f;
    public final String g;
    public final String h;
    public final String i;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudyNotesArtifactsResponse$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudyNotesArtifactsResponse(int i, String str, String str2, long j, String str3, com.quizlet.shared.enums.studynotes.d dVar, String str4, String str5, String str6, String str7) {
        if (255 != (i & 255)) {
            AbstractC5047c0.k(i, 255, StudyNotesArtifactsResponse$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = str2;
        this.c = j;
        this.d = str3;
        this.e = dVar;
        this.f = str4;
        this.g = str5;
        this.h = str6;
        if ((i & 256) == 0) {
            this.i = null;
        } else {
            this.i = str7;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyNotesArtifactsResponse)) {
            return false;
        }
        StudyNotesArtifactsResponse studyNotesArtifactsResponse = (StudyNotesArtifactsResponse) obj;
        return Intrinsics.b(this.a, studyNotesArtifactsResponse.a) && Intrinsics.b(this.b, studyNotesArtifactsResponse.b) && this.c == studyNotesArtifactsResponse.c && Intrinsics.b(this.d, studyNotesArtifactsResponse.d) && this.e == studyNotesArtifactsResponse.e && Intrinsics.b(this.f, studyNotesArtifactsResponse.f) && Intrinsics.b(this.g, studyNotesArtifactsResponse.g) && Intrinsics.b(this.h, studyNotesArtifactsResponse.h) && Intrinsics.b(this.i, studyNotesArtifactsResponse.i);
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(d0.e((this.e.hashCode() + d0.e(d0.d(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d)) * 31, 31, this.f), 31, this.g), 31, this.h);
        String str = this.i;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudyNotesArtifactsResponse(uuid=");
        sb.append(this.a);
        sb.append(", noteUuid=");
        sb.append(this.b);
        sb.append(", userId=");
        sb.append(this.c);
        sb.append(", type=");
        sb.append(this.d);
        sb.append(", status=");
        sb.append(this.e);
        sb.append(", content=");
        sb.append(this.f);
        sb.append(", createdAt=");
        sb.append(this.g);
        sb.append(", updatedAt=");
        sb.append(this.h);
        sb.append(", history=");
        return android.support.v4.media.session.a.t(sb, this.i, ")");
    }
}
