package com.quizlet.shared.models.folderstudymaterials;

import androidx.compose.animation.d0;
import com.quizlet.shared.enums.p;
import com.quizlet.shared.models.folders.Folder;
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
public final class FolderStudyMaterial$FolderMaterial extends e implements a {

    @NotNull
    public static final Companion Companion = new Companion();
    public final Folder b;
    public final long c;
    public final long d;
    public final String e;
    public final p f;
    public final String g;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return FolderStudyMaterial$FolderMaterial$$serializer.INSTANCE;
        }
    }

    public FolderStudyMaterial$FolderMaterial(int i, Folder folder, long j, long j2, String str, p pVar, String str2) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, FolderStudyMaterial$FolderMaterial$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = folder;
        this.c = j;
        this.d = j2;
        if ((i & 8) == 0) {
            this.e = String.valueOf(folder.c);
        } else {
            this.e = str;
        }
        if ((i & 16) == 0) {
            this.f = p.c;
        } else {
            this.f = pVar;
        }
        if ((i & 32) == 0) {
            this.g = folder.e;
        } else {
            this.g = str2;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof FolderStudyMaterial$FolderMaterial)) {
            return false;
        }
        FolderStudyMaterial$FolderMaterial folderStudyMaterial$FolderMaterial = (FolderStudyMaterial$FolderMaterial) obj;
        return Intrinsics.b(this.b, folderStudyMaterial$FolderMaterial.b) && this.c == folderStudyMaterial$FolderMaterial.c && this.d == folderStudyMaterial$FolderMaterial.d;
    }

    public final int hashCode() {
        return Long.hashCode(this.d) + d0.d(this.b.hashCode() * 31, 31, this.c);
    }

    public final String toString() {
        return "FolderMaterial(data=" + this.b + ", id=" + this.c + ", timestampSec=" + this.d + ")";
    }
}
