package com.quizlet.remote.model.notes;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.user.RemoteUser;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class StudyNoteModel {
    public final List a;
    public final List b;
    public final List c;

    public StudyNoteModel(@InterfaceC4853h(name = "magicNote") @NotNull List<MagicNotesResponse> magicNotes, @InterfaceC4853h(name = "artifact") @NotNull List<MagicNotesArtifactResponse> artifacts, @InterfaceC4853h(name = "user") @NotNull List<RemoteUser> users) {
        Intrinsics.checkNotNullParameter(magicNotes, "magicNotes");
        Intrinsics.checkNotNullParameter(artifacts, "artifacts");
        Intrinsics.checkNotNullParameter(users, "users");
        this.a = magicNotes;
        this.b = artifacts;
        this.c = users;
    }

    @NotNull
    public final StudyNoteModel copy(@InterfaceC4853h(name = "magicNote") @NotNull List<MagicNotesResponse> magicNotes, @InterfaceC4853h(name = "artifact") @NotNull List<MagicNotesArtifactResponse> artifacts, @InterfaceC4853h(name = "user") @NotNull List<RemoteUser> users) {
        Intrinsics.checkNotNullParameter(magicNotes, "magicNotes");
        Intrinsics.checkNotNullParameter(artifacts, "artifacts");
        Intrinsics.checkNotNullParameter(users, "users");
        return new StudyNoteModel(magicNotes, artifacts, users);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyNoteModel)) {
            return false;
        }
        StudyNoteModel studyNoteModel = (StudyNoteModel) obj;
        return Intrinsics.b(this.a, studyNoteModel.a) && Intrinsics.b(this.b, studyNoteModel.b) && Intrinsics.b(this.c, studyNoteModel.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + d0.f(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudyNoteModel(magicNotes=");
        sb.append(this.a);
        sb.append(", artifacts=");
        sb.append(this.b);
        sb.append(", users=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }

    public StudyNoteModel(List list, List list2, List list3, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list, (i & 2) != 0 ? K.a : list2, (i & 4) != 0 ? K.a : list3);
    }
}
