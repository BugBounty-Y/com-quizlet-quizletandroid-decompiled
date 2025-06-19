package com.quizlet.shared.models.api.folderstudymaterials;

import androidx.compose.animation.d0;
import com.quizlet.shared.enums.o;
import java.util.List;
import kotlin.Metadata;
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
public final class GetFolderStudyMaterialsByFolderIdAndType extends a {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] e = {new C5048d(P.a, 0), new C5048d(o.f, 0), null};
    public final List b;
    public final List c;
    public final boolean d;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return GetFolderStudyMaterialsByFolderIdAndType$$serializer.INSTANCE;
        }
    }

    public GetFolderStudyMaterialsByFolderIdAndType(int i, List list, List list2, boolean z) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, GetFolderStudyMaterialsByFolderIdAndType$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = list;
        this.c = list2;
        if ((i & 4) == 0) {
            this.d = true;
        } else {
            this.d = z;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof GetFolderStudyMaterialsByFolderIdAndType)) {
            return false;
        }
        GetFolderStudyMaterialsByFolderIdAndType getFolderStudyMaterialsByFolderIdAndType = (GetFolderStudyMaterialsByFolderIdAndType) obj;
        return Intrinsics.b(this.b, getFolderStudyMaterialsByFolderIdAndType.b) && Intrinsics.b(this.c, getFolderStudyMaterialsByFolderIdAndType.c) && this.d == getFolderStudyMaterialsByFolderIdAndType.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.f(this.b.hashCode() * 31, 31, this.c);
    }

    @Override // com.quizlet.shared.models.api.folderstudymaterials.a
    public final List j() {
        return this.b;
    }

    @Override // com.quizlet.shared.models.api.folderstudymaterials.a
    public final boolean k() {
        return this.d;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GetFolderStudyMaterialsByFolderIdAndType(folderIds=");
        sb.append(this.b);
        sb.append(", types=");
        sb.append(this.c);
        sb.append(", includeModels=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
