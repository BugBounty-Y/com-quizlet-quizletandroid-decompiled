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
public final class StudyNoteArtifactInfo$Title extends b {

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
            return StudyNoteArtifactInfo$Title$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudyNoteArtifactInfo$Title(int i, String str, d dVar, String str2, com.quizlet.shared.enums.studynotes.f fVar) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, StudyNoteArtifactInfo$Title$$serializer.INSTANCE.getDescriptor());
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
            this.f = com.quizlet.shared.enums.studynotes.f.b;
        } else {
            this.f = fVar;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyNoteArtifactInfo$Title)) {
            return false;
        }
        StudyNoteArtifactInfo$Title studyNoteArtifactInfo$Title = (StudyNoteArtifactInfo$Title) obj;
        return Intrinsics.b(this.c, studyNoteArtifactInfo$Title.c) && this.d == studyNoteArtifactInfo$Title.d && Intrinsics.b(this.e, studyNoteArtifactInfo$Title.e);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + (this.c.hashCode() * 31)) * 31;
        String str = this.e;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Title(uuid=");
        sb.append(this.c);
        sb.append(", status=");
        sb.append(this.d);
        sb.append(", title=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }

    public StudyNoteArtifactInfo$Title(String uuid, d status, String str) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(status, "status");
        this.c = uuid;
        this.d = status;
        this.e = str;
        this.f = com.quizlet.shared.enums.studynotes.f.b;
    }
}
