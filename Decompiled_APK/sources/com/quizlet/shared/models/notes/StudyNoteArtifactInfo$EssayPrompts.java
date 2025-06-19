package com.quizlet.shared.models.notes;

import com.quizlet.shared.enums.studynotes.d;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class StudyNoteArtifactInfo$EssayPrompts extends b {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] g = {null, null, new C5048d(EssayPromptItem$$serializer.INSTANCE, 0), null};
    public final String c;
    public final d d;
    public final List e;
    public final com.quizlet.shared.enums.studynotes.f f;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudyNoteArtifactInfo$EssayPrompts$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudyNoteArtifactInfo$EssayPrompts(int i, String str, d dVar, List list, com.quizlet.shared.enums.studynotes.f fVar) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, StudyNoteArtifactInfo$EssayPrompts$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.c = str;
        this.d = dVar;
        if ((i & 4) == 0) {
            this.e = null;
        } else {
            this.e = list;
        }
        if ((i & 8) == 0) {
            this.f = com.quizlet.shared.enums.studynotes.f.c;
        } else {
            this.f = fVar;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyNoteArtifactInfo$EssayPrompts)) {
            return false;
        }
        StudyNoteArtifactInfo$EssayPrompts studyNoteArtifactInfo$EssayPrompts = (StudyNoteArtifactInfo$EssayPrompts) obj;
        return Intrinsics.b(this.c, studyNoteArtifactInfo$EssayPrompts.c) && this.d == studyNoteArtifactInfo$EssayPrompts.d && Intrinsics.b(this.e, studyNoteArtifactInfo$EssayPrompts.e);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + (this.c.hashCode() * 31)) * 31;
        List list = this.e;
        return iHashCode + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("EssayPrompts(uuid=");
        sb.append(this.c);
        sb.append(", status=");
        sb.append(this.d);
        sb.append(", prompts=");
        return android.support.v4.media.session.a.n(")", sb, this.e);
    }

    public StudyNoteArtifactInfo$EssayPrompts(String uuid, d status, ArrayList arrayList) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(status, "status");
        this.c = uuid;
        this.d = status;
        this.e = arrayList;
        this.f = com.quizlet.shared.enums.studynotes.f.c;
    }
}
