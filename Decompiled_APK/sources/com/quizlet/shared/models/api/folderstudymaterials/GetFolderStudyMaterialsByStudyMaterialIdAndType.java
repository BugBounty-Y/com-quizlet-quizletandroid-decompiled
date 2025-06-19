package com.quizlet.shared.models.api.folderstudymaterials;

import androidx.compose.animation.d0;
import com.quizlet.shared.enums.p;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.P;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class GetFolderStudyMaterialsByStudyMaterialIdAndType extends a {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] f = {null, null, new C5048d(P.a, 0), null};
    public final String b;
    public final p c;
    public final List d;
    public final boolean e;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return GetFolderStudyMaterialsByStudyMaterialIdAndType$$serializer.INSTANCE;
        }
    }

    public GetFolderStudyMaterialsByStudyMaterialIdAndType(int i, String str, p pVar, List list, boolean z) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, GetFolderStudyMaterialsByStudyMaterialIdAndType$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = str;
        this.c = pVar;
        if ((i & 4) == 0) {
            this.d = K.a;
        } else {
            this.d = list;
        }
        if ((i & 8) == 0) {
            this.e = true;
        } else {
            this.e = z;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GetFolderStudyMaterialsByStudyMaterialIdAndType)) {
            return false;
        }
        GetFolderStudyMaterialsByStudyMaterialIdAndType getFolderStudyMaterialsByStudyMaterialIdAndType = (GetFolderStudyMaterialsByStudyMaterialIdAndType) obj;
        return Intrinsics.b(this.b, getFolderStudyMaterialsByStudyMaterialIdAndType.b) && this.c == getFolderStudyMaterialsByStudyMaterialIdAndType.c && Intrinsics.b(this.d, getFolderStudyMaterialsByStudyMaterialIdAndType.d) && this.e == getFolderStudyMaterialsByStudyMaterialIdAndType.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + d0.f((this.c.hashCode() + (this.b.hashCode() * 31)) * 31, 31, this.d);
    }

    @Override // com.quizlet.shared.models.api.folderstudymaterials.a
    public final List j() {
        return this.d;
    }

    @Override // com.quizlet.shared.models.api.folderstudymaterials.a
    public final boolean k() {
        return this.e;
    }

    public final String toString() {
        return "GetFolderStudyMaterialsByStudyMaterialIdAndType(studyMaterialId=" + this.b + ", studyMaterialType=" + this.c + ", folderIds=" + this.d + ", includeModels=" + this.e + ")";
    }
}
