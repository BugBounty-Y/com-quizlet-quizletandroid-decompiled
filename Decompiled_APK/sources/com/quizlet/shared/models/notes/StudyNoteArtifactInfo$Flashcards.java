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
public final class StudyNoteArtifactInfo$Flashcards extends b {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] h = {null, null, null, new C5048d(FlashcardItem$$serializer.INSTANCE, 0), null};
    public final String c;
    public final d d;
    public final Long e;
    public final List f;
    public final com.quizlet.shared.enums.studynotes.f g;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return StudyNoteArtifactInfo$Flashcards$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ StudyNoteArtifactInfo$Flashcards(int i, String str, d dVar, Long l, List list, com.quizlet.shared.enums.studynotes.f fVar) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, StudyNoteArtifactInfo$Flashcards$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.c = str;
        this.d = dVar;
        if ((i & 4) == 0) {
            this.e = null;
        } else {
            this.e = l;
        }
        if ((i & 8) == 0) {
            this.f = null;
        } else {
            this.f = list;
        }
        if ((i & 16) == 0) {
            this.g = com.quizlet.shared.enums.studynotes.f.e;
        } else {
            this.g = fVar;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyNoteArtifactInfo$Flashcards)) {
            return false;
        }
        StudyNoteArtifactInfo$Flashcards studyNoteArtifactInfo$Flashcards = (StudyNoteArtifactInfo$Flashcards) obj;
        return Intrinsics.b(this.c, studyNoteArtifactInfo$Flashcards.c) && this.d == studyNoteArtifactInfo$Flashcards.d && Intrinsics.b(this.e, studyNoteArtifactInfo$Flashcards.e) && Intrinsics.b(this.f, studyNoteArtifactInfo$Flashcards.f);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + (this.c.hashCode() * 31)) * 31;
        Long l = this.e;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        List list = this.f;
        return iHashCode2 + (list != null ? list.hashCode() : 0);
    }

    public final String toString() {
        return "Flashcards(uuid=" + this.c + ", status=" + this.d + ", setId=" + this.e + ", cards=" + this.f + ")";
    }

    public StudyNoteArtifactInfo$Flashcards(String uuid, d status, Long l, ArrayList arrayList) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(status, "status");
        this.c = uuid;
        this.d = status;
        this.e = l;
        this.f = arrayList;
        this.g = com.quizlet.shared.enums.studynotes.f.e;
    }
}
