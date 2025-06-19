package com.quizlet.shared.models.notes;

import com.quizlet.shared.enums.studynotes.d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class StudyNoteArtifactInfo$ReviewSheet extends b {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String c;
    public final d d;
    public final String e;
    public final com.quizlet.shared.enums.studynotes.f f;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudyNoteArtifactInfo$ReviewSheet$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudyNoteArtifactInfo$ReviewSheet(int i, String str, d dVar, String str2, com.quizlet.shared.enums.studynotes.f fVar) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, StudyNoteArtifactInfo$ReviewSheet$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.c = str;
        this.d = dVar;
        if ((i & 4) == 0) {
            this.e = null;
        } else {
            this.e = str2;
        }
        if ((i & 8) == 0) {
            this.f = com.quizlet.shared.enums.studynotes.f.f;
        } else {
            this.f = fVar;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyNoteArtifactInfo$ReviewSheet)) {
            return false;
        }
        StudyNoteArtifactInfo$ReviewSheet studyNoteArtifactInfo$ReviewSheet = (StudyNoteArtifactInfo$ReviewSheet) obj;
        return Intrinsics.b(this.c, studyNoteArtifactInfo$ReviewSheet.c) && this.d == studyNoteArtifactInfo$ReviewSheet.d && Intrinsics.b(this.e, studyNoteArtifactInfo$ReviewSheet.e);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + (this.c.hashCode() * 31)) * 31;
        String str = this.e;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ReviewSheet(uuid=");
        sb.append(this.c);
        sb.append(", status=");
        sb.append(this.d);
        sb.append(", reviewSheet=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }

    public StudyNoteArtifactInfo$ReviewSheet(String uuid, d status, String str) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(status, "status");
        this.c = uuid;
        this.d = status;
        this.e = str;
        this.f = com.quizlet.shared.enums.studynotes.f.f;
    }
}
