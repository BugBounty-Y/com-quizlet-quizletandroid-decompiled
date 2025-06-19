package com.quizlet.shared.models.folderstudymaterials;

import androidx.compose.animation.d0;
import com.quizlet.shared.enums.p;
import com.quizlet.shared.models.notes.FullStudyNotesInfo;
import com.quizlet.shared.models.notes.FullStudyNotesInfo$$serializer;
import com.quizlet.shared.models.notes.NewStudyNotesInfo;
import com.quizlet.shared.models.notes.NewStudyNotesInfo$$serializer;
import com.quizlet.shared.models.notes.StudyNoteArtifactInfo$Title;
import com.quizlet.shared.models.notes.c;
import com.quizlet.shared.models.user.User;
import java.lang.annotation.Annotation;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class FolderStudyMaterial$NoteMaterial extends e implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] i = {new kotlinx.serialization.e("StudyNotesInfo", K.a(c.class), new kotlin.reflect.c[]{K.a(FullStudyNotesInfo.class), K.a(NewStudyNotesInfo.class)}, new KSerializer[]{FullStudyNotesInfo$$serializer.INSTANCE, NewStudyNotesInfo$$serializer.INSTANCE}, new Annotation[0]), null, null, null, null, null, null};
    public final c b;
    public final User c;
    public final long d;
    public final long e;
    public final String f;
    public final p g;
    public final String h;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FolderStudyMaterial$NoteMaterial$$serializer.INSTANCE;
        }
    }

    public FolderStudyMaterial$NoteMaterial(int i2, c cVar, User user, long j, long j2, String str, p pVar, String str2) {
        if (15 != (i2 & 15)) {
            AbstractC5047c0.k(i2, 15, FolderStudyMaterial$NoteMaterial$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = cVar;
        this.c = user;
        this.d = j;
        this.e = j2;
        if ((i2 & 16) == 0) {
            this.f = cVar.b();
        } else {
            this.f = str;
        }
        if ((i2 & 32) == 0) {
            this.g = p.g;
        } else {
            this.g = pVar;
        }
        if ((i2 & 64) != 0) {
            this.h = str2;
        } else {
            StudyNoteArtifactInfo$Title title = cVar.getTitle();
            this.h = title != null ? title.e : null;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FolderStudyMaterial$NoteMaterial)) {
            return false;
        }
        FolderStudyMaterial$NoteMaterial folderStudyMaterial$NoteMaterial = (FolderStudyMaterial$NoteMaterial) obj;
        return Intrinsics.b(this.b, folderStudyMaterial$NoteMaterial.b) && Intrinsics.b(this.c, folderStudyMaterial$NoteMaterial.c) && this.d == folderStudyMaterial$NoteMaterial.d && this.e == folderStudyMaterial$NoteMaterial.e;
    }

    public final int hashCode() {
        return Long.hashCode(this.e) + d0.d((this.c.hashCode() + (this.b.hashCode() * 31)) * 31, 31, this.d);
    }

    public final String toString() {
        return "NoteMaterial(data=" + this.b + ", user=" + this.c + ", id=" + this.d + ", timestampSec=" + this.e + ")";
    }
}
