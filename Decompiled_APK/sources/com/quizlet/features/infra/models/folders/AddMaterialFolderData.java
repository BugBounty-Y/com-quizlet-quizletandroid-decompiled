package com.quizlet.features.infra.models.folders;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.onetrust.otpublishers.headless.UI.DataModels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class AddMaterialFolderData implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<AddMaterialFolderData> CREATOR = new f(5);
    public final long a;
    public final String b;
    public final boolean c;

    public AddMaterialFolderData(String folderName, long j, boolean z) {
        Intrinsics.checkNotNullParameter(folderName, "folderName");
        this.a = j;
        this.b = folderName;
        this.c = z;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AddMaterialFolderData)) {
            return false;
        }
        AddMaterialFolderData addMaterialFolderData = (AddMaterialFolderData) obj;
        return this.a == addMaterialFolderData.a && Intrinsics.b(this.b, addMaterialFolderData.b) && this.c == addMaterialFolderData.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.e(Long.hashCode(this.a) * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AddMaterialFolderData(folderId=");
        sb.append(this.a);
        sb.append(", folderName=");
        sb.append(this.b);
        sb.append(", didAdd=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeLong(this.a);
        dest.writeString(this.b);
        dest.writeInt(this.c ? 1 : 0);
    }
}
