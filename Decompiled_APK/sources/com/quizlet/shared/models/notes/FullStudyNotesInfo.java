package com.quizlet.shared.models.notes;

import androidx.compose.animation.d0;
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
public final class FullStudyNotesInfo extends e implements c {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String b;
    public final long c;
    public final String d;
    public final boolean e;
    public final String f;
    public final String g;
    public final StudyNoteArtifactInfo$Title h;
    public final StudyNoteArtifactInfo$OutlineMarkdown i;
    public final StudyNoteArtifactInfo$ReviewSheet j;
    public final StudyNoteArtifactInfo$Flashcards k;
    public final StudyNoteArtifactInfo$EssayPrompts l;
    public final String m;
    public final boolean n;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FullStudyNotesInfo$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ FullStudyNotesInfo(int i, String str, long j, String str2, boolean z, String str3, String str4, StudyNoteArtifactInfo$Title studyNoteArtifactInfo$Title, StudyNoteArtifactInfo$OutlineMarkdown studyNoteArtifactInfo$OutlineMarkdown, StudyNoteArtifactInfo$ReviewSheet studyNoteArtifactInfo$ReviewSheet, StudyNoteArtifactInfo$Flashcards studyNoteArtifactInfo$Flashcards, StudyNoteArtifactInfo$EssayPrompts studyNoteArtifactInfo$EssayPrompts, String str5, boolean z2) {
        if (4095 != (i & 4095)) {
            AbstractC5047c0.k(i, 4095, FullStudyNotesInfo$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = str;
        this.c = j;
        this.d = str2;
        this.e = z;
        this.f = str3;
        this.g = str4;
        this.h = studyNoteArtifactInfo$Title;
        this.i = studyNoteArtifactInfo$OutlineMarkdown;
        this.j = studyNoteArtifactInfo$ReviewSheet;
        this.k = studyNoteArtifactInfo$Flashcards;
        this.l = studyNoteArtifactInfo$EssayPrompts;
        this.m = str5;
        this.n = (i & 4096) == 0 ? false : z2;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final StudyNoteArtifactInfo$OutlineMarkdown a() {
        return this.i;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final String b() {
        return this.b;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final StudyNoteArtifactInfo$EssayPrompts c() {
        return this.l;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final Boolean d() {
        return Boolean.valueOf(this.e);
    }

    @Override // com.quizlet.shared.models.notes.c
    public final StudyNoteArtifactInfo$ReviewSheet e() {
        return this.j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FullStudyNotesInfo)) {
            return false;
        }
        FullStudyNotesInfo fullStudyNotesInfo = (FullStudyNotesInfo) obj;
        return Intrinsics.b(this.b, fullStudyNotesInfo.b) && this.c == fullStudyNotesInfo.c && Intrinsics.b(this.d, fullStudyNotesInfo.d) && this.e == fullStudyNotesInfo.e && Intrinsics.b(this.f, fullStudyNotesInfo.f) && Intrinsics.b(this.g, fullStudyNotesInfo.g) && Intrinsics.b(this.h, fullStudyNotesInfo.h) && Intrinsics.b(this.i, fullStudyNotesInfo.i) && Intrinsics.b(this.j, fullStudyNotesInfo.j) && Intrinsics.b(this.k, fullStudyNotesInfo.k) && Intrinsics.b(this.l, fullStudyNotesInfo.l) && Intrinsics.b(this.m, fullStudyNotesInfo.m) && this.n == fullStudyNotesInfo.n;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final String f() {
        return this.f;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final String g() {
        return this.g;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final StudyNoteArtifactInfo$Title getTitle() {
        return this.h;
    }

    @Override // com.quizlet.shared.models.notes.c
    public final String h() {
        return this.m;
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(d0.g(d0.e(d0.d(this.b.hashCode() * 31, 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g);
        StudyNoteArtifactInfo$Title studyNoteArtifactInfo$Title = this.h;
        int iHashCode = (iE + (studyNoteArtifactInfo$Title == null ? 0 : studyNoteArtifactInfo$Title.hashCode())) * 31;
        StudyNoteArtifactInfo$OutlineMarkdown studyNoteArtifactInfo$OutlineMarkdown = this.i;
        int iHashCode2 = (iHashCode + (studyNoteArtifactInfo$OutlineMarkdown == null ? 0 : studyNoteArtifactInfo$OutlineMarkdown.hashCode())) * 31;
        StudyNoteArtifactInfo$ReviewSheet studyNoteArtifactInfo$ReviewSheet = this.j;
        int iHashCode3 = (iHashCode2 + (studyNoteArtifactInfo$ReviewSheet == null ? 0 : studyNoteArtifactInfo$ReviewSheet.hashCode())) * 31;
        StudyNoteArtifactInfo$Flashcards studyNoteArtifactInfo$Flashcards = this.k;
        int iHashCode4 = (iHashCode3 + (studyNoteArtifactInfo$Flashcards == null ? 0 : studyNoteArtifactInfo$Flashcards.hashCode())) * 31;
        StudyNoteArtifactInfo$EssayPrompts studyNoteArtifactInfo$EssayPrompts = this.l;
        int iHashCode5 = (iHashCode4 + (studyNoteArtifactInfo$EssayPrompts == null ? 0 : studyNoteArtifactInfo$EssayPrompts.hashCode())) * 31;
        String str = this.m;
        return Boolean.hashCode(this.n) + ((iHashCode5 + (str != null ? str.hashCode() : 0)) * 31);
    }

    @Override // com.quizlet.shared.models.notes.c
    public final StudyNoteArtifactInfo$Flashcards i() {
        return this.k;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FullStudyNotesInfo(uuid=");
        sb.append(this.b);
        sb.append(", userId=");
        sb.append(this.c);
        sb.append(", documentType=");
        sb.append(this.d);
        sb.append(", isPrivate=");
        sb.append(this.e);
        sb.append(", extractedText=");
        sb.append(this.f);
        sb.append(", createdAt=");
        sb.append(this.g);
        sb.append(", title=");
        sb.append(this.h);
        sb.append(", outlineMarkdown=");
        sb.append(this.i);
        sb.append(", reviewSheet=");
        sb.append(this.j);
        sb.append(", flashcards=");
        sb.append(this.k);
        sb.append(", essay=");
        sb.append(this.l);
        sb.append(", userModifiedAt=");
        sb.append(this.m);
        sb.append(", redirectToWeb=");
        return android.support.v4.media.session.a.o(")", sb, this.n);
    }

    public FullStudyNotesInfo(String uuid, long j, String documentType, boolean z, String extractedText, String createdAt, StudyNoteArtifactInfo$Title studyNoteArtifactInfo$Title, StudyNoteArtifactInfo$OutlineMarkdown studyNoteArtifactInfo$OutlineMarkdown, StudyNoteArtifactInfo$ReviewSheet studyNoteArtifactInfo$ReviewSheet, StudyNoteArtifactInfo$Flashcards studyNoteArtifactInfo$Flashcards, StudyNoteArtifactInfo$EssayPrompts studyNoteArtifactInfo$EssayPrompts, String str, boolean z2) {
        Intrinsics.checkNotNullParameter(uuid, "uuid");
        Intrinsics.checkNotNullParameter(documentType, "documentType");
        Intrinsics.checkNotNullParameter(extractedText, "extractedText");
        Intrinsics.checkNotNullParameter(createdAt, "createdAt");
        this.b = uuid;
        this.c = j;
        this.d = documentType;
        this.e = z;
        this.f = extractedText;
        this.g = createdAt;
        this.h = studyNoteArtifactInfo$Title;
        this.i = studyNoteArtifactInfo$OutlineMarkdown;
        this.j = studyNoteArtifactInfo$ReviewSheet;
        this.k = studyNoteArtifactInfo$Flashcards;
        this.l = studyNoteArtifactInfo$EssayPrompts;
        this.m = str;
        this.n = z2;
    }
}
