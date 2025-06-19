package com.quizlet.shared.models.api.folderstudymaterials;

import androidx.compose.animation.d0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class RemoteFolderStudyMaterialData {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long a;
    public final String b;
    public final int c;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return RemoteFolderStudyMaterialData$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ RemoteFolderStudyMaterialData(long j, int i, int i2, String str) {
        if (7 != (i & 7)) {
            AbstractC5047c0.k(i, 7, RemoteFolderStudyMaterialData$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = j;
        this.b = str;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteFolderStudyMaterialData)) {
            return false;
        }
        RemoteFolderStudyMaterialData remoteFolderStudyMaterialData = (RemoteFolderStudyMaterialData) obj;
        return this.a == remoteFolderStudyMaterialData.a && Intrinsics.b(this.b, remoteFolderStudyMaterialData.b) && this.c == remoteFolderStudyMaterialData.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.e(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteFolderStudyMaterialData(folderId=");
        sb.append(this.a);
        sb.append(", studyMaterialId=");
        sb.append(this.b);
        sb.append(", studyMaterialType=");
        return android.support.v4.media.session.a.r(sb, this.c, ")");
    }
}
