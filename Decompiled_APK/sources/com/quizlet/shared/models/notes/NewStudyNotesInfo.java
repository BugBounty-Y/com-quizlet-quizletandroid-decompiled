package com.quizlet.shared.models.notes;

import androidx.compose.animation.d0;
import com.google.android.gms.ads.g;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class NewStudyNotesInfo extends e implements c {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String b;
    public final long c;
    public final StudyNoteArtifactInfo$Title d;
    public final StudyNoteArtifactInfo$OutlineMarkdown e;
    public final StudyNoteArtifactInfo$ReviewSheet f;
    public final StudyNoteArtifactInfo$Flashcards g;
    public final StudyNoteArtifactInfo$EssayPrompts h;
    public final boolean i;
    public final String j;
    public final Boolean k;
    public final String l;
    public final String m;
    public final String n;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return NewStudyNotesInfo$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ NewStudyNotesInfo(int i, String str, long j, StudyNoteArtifactInfo$Title studyNoteArtifactInfo$Title, StudyNoteArtifactInfo$OutlineMarkdown studyNoteArtifactInfo$OutlineMarkdown, StudyNoteArtifactInfo$ReviewSheet studyNoteArtifactInfo$ReviewSheet, StudyNoteArtifactInfo$Flashcards studyNoteArtifactInfo$Flashcards, StudyNoteArtifactInfo$EssayPrompts studyNoteArtifactInfo$EssayPrompts, boolean z, String str2, Boolean bool, String str3, String str4, String str5) {
        if (127 != (i & 127)) {
            AbstractC5047c0.k(i, 127, NewStudyNotesInfo$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = str;
        this.c = j;
        this.d = studyNoteArtifactInfo$Title;
        this.e = studyNoteArtifactInfo$OutlineMarkdown;
        this.f = studyNoteArtifactInfo$ReviewSheet;
        this.g = studyNoteArtifactInfo$Flashcards;
        this.h = studyNoteArtifactInfo$EssayPrompts;
        if ((i & 128) == 0) {
            this.i = false;
        } else {
            this.i = z;
        }
        if ((i & 256) == 0) {
            this.j = null;
        } else {
            this.j = str2;
        }
        if ((i & g.MAX_CONTENT_URL_LENGTH) == 0) {
            this.k = null;
        } else {
            this.k = bool;
        }
        if ((i & 1024) == 0) {
            this.l = null;
        } else {
            this.l = str3;
        }
        if ((i & 2048) == 0) {
            this.m = null;
        } else {
            this.m = str4;
        }
        if ((i & 4096) == 0) {
            this.n = null;
        } else {
            this.n = str5;
        }
    }

    @Override // com.quizlet.shared.models.notes.c
    public final StudyNoteArtifactInfo$OutlineMarkdown a() {
        return this.e;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final String b() {
        return this.b;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final StudyNoteArtifactInfo$EssayPrompts c() {
        return this.h;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final Boolean d() {
        return this.k;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final StudyNoteArtifactInfo$ReviewSheet e() {
        return this.f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof NewStudyNotesInfo)) {
            return false;
        }
        NewStudyNotesInfo newStudyNotesInfo = (NewStudyNotesInfo) obj;
        return Intrinsics.b(this.b, newStudyNotesInfo.b) && this.c == newStudyNotesInfo.c && Intrinsics.b(this.d, newStudyNotesInfo.d) && Intrinsics.b(this.e, newStudyNotesInfo.e) && Intrinsics.b(this.f, newStudyNotesInfo.f) && Intrinsics.b(this.g, newStudyNotesInfo.g) && Intrinsics.b(this.h, newStudyNotesInfo.h) && this.i == newStudyNotesInfo.i;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final String f() {
        return this.l;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final String g() {
        return this.m;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final StudyNoteArtifactInfo$Title getTitle() {
        return this.d;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final String h() {
        return this.n;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.i) + ((this.h.hashCode() + ((this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + d0.d(this.b.hashCode() * 31, 31, this.c)) * 31)) * 31)) * 31)) * 31)) * 31);
    }

    @Override // com.quizlet.shared.models.notes.c
    public final StudyNoteArtifactInfo$Flashcards i() {
        return this.g;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NewStudyNotesInfo(uuid=");
        sb.append(this.b);
        sb.append(", userId=");
        sb.append(this.c);
        sb.append(", title=");
        sb.append(this.d);
        sb.append(", outlineMarkdown=");
        sb.append(this.e);
        sb.append(", reviewSheet=");
        sb.append(this.f);
        sb.append(", flashcards=");
        sb.append(this.g);
        sb.append(", essay=");
        sb.append(this.h);
        sb.append(", redirectToWeb=");
        return android.support.v4.media.session.a.o(")", sb, this.i);
    }

    public NewStudyNotesInfo(String uuid, long j, StudyNoteArtifactInfo$Title title, StudyNoteArtifactInfo$OutlineMarkdown outlineMarkdown, StudyNoteArtifactInfo$ReviewSheet reviewSheet, StudyNoteArtifactInfo$Flashcards flashcards, StudyNoteArtifactInfo$EssayPrompts essay, boolean z) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(outlineMarkdown, "outlineMarkdown");
        Intrinsics.checkNotNullParameter(reviewSheet, "reviewSheet");
        Intrinsics.checkNotNullParameter(flashcards, "flashcards");
        Intrinsics.checkNotNullParameter(essay, "essay");
        this.b = uuid;
        this.c = j;
        this.d = title;
        this.e = outlineMarkdown;
        this.f = reviewSheet;
        this.g = flashcards;
        this.h = essay;
        this.i = z;
    }
}
