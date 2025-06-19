package com.quizlet.remote.model.foldertoadd;

import androidx.compose.animation.d0;
import com.quizlet.remote.model.base.ApiResponse;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class FolderToAddMaterialResponse extends ApiResponse {
    public final List d;

    @m(generateAdapter = true)
    @Metadata
    public static final class FolderToAddData {
        public final List a;

        public FolderToAddData(@InterfaceC4853h(name = "foldersToAddStudyMaterialsTo") @NotNull List<FolderToAddModel> foldersToAddStudyMaterialsTo) {
            Intrinsics.checkNotNullParameter(foldersToAddStudyMaterialsTo, "foldersToAddStudyMaterialsTo");
            this.a = foldersToAddStudyMaterialsTo;
        }

        @NotNull
        public final FolderToAddData copy(@InterfaceC4853h(name = "foldersToAddStudyMaterialsTo") @NotNull List<FolderToAddModel> foldersToAddStudyMaterialsTo) {
            Intrinsics.checkNotNullParameter(foldersToAddStudyMaterialsTo, "foldersToAddStudyMaterialsTo");
            return new FolderToAddData(foldersToAddStudyMaterialsTo);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            return (obj instanceof FolderToAddData) && Intrinsics.b(this.a, ((FolderToAddData) obj).a);
        }

        public final int hashCode() {
            return this.a.hashCode();
        }

        public final String toString() {
            return android.support.v4.media.session.a.n(")", new StringBuilder("FolderToAddData(foldersToAddStudyMaterialsTo="), this.a);
        }
    }

    public /* synthetic */ FolderToAddMaterialResponse(List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : list);
    }

    @NotNull
    public final FolderToAddMaterialResponse copy(@InterfaceC4853h(name = "data") List<FolderToAddData> list) {
        return new FolderToAddMaterialResponse(list);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof FolderToAddMaterialResponse) && Intrinsics.b(this.d, ((FolderToAddMaterialResponse) obj).d);
    }

    public final int hashCode() {
        List list = this.d;
        if (list == null) {
            return 0;
        }
        return list.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("FolderToAddMaterialResponse(data="), this.d);
    }

    public FolderToAddMaterialResponse(@InterfaceC4853h(name = "data") List<FolderToAddData> list) {
        this.d = list;
    }

    @m(generateAdapter = true)
    @Metadata
    public static final class FolderToAddModel {
        public final long a;
        public final String b;
        public final boolean c;
        public final List d;

        public FolderToAddModel(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "title") @NotNull String folderName, @InterfaceC4853h(name = "isAlreadyAdded") boolean z, @InterfaceC4853h(name = "subfolders") List<FolderToAddModel> list) {
            Intrinsics.checkNotNullParameter(folderName, "folderName");
            this.a = j;
            this.b = folderName;
            this.c = z;
            this.d = list;
        }

        @NotNull
        public final FolderToAddModel copy(@InterfaceC4853h(name = "id") long j, @InterfaceC4853h(name = "title") @NotNull String folderName, @InterfaceC4853h(name = "isAlreadyAdded") boolean z, @InterfaceC4853h(name = "subfolders") List<FolderToAddModel> list) {
            Intrinsics.checkNotNullParameter(folderName, "folderName");
            return new FolderToAddModel(j, folderName, z, list);
        }

        public final boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof FolderToAddModel)) {
                return false;
            }
            FolderToAddModel folderToAddModel = (FolderToAddModel) obj;
            return this.a == folderToAddModel.a && Intrinsics.b(this.b, folderToAddModel.b) && this.c == folderToAddModel.c && Intrinsics.b(this.d, folderToAddModel.d);
        }

        public final int hashCode() {
            int iG = d0.g(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
            List list = this.d;
            return iG + (list == null ? 0 : list.hashCode());
        }

        public final String toString() {
            StringBuilder sb = new StringBuilder("FolderToAddModel(id=");
            sb.append(this.a);
            sb.append(", folderName=");
            sb.append(this.b);
            sb.append(", isAlreadyAddedToFolder=");
            sb.append(this.c);
            sb.append(", subfolders=");
            return android.support.v4.media.session.a.n(")", sb, this.d);
        }

        public /* synthetic */ FolderToAddModel(long j, String str, boolean z, List list, int i, DefaultConstructorMarker defaultConstructorMarker) {
            this(j, str, z, (i & 8) != 0 ? null : list);
        }
    }
}
