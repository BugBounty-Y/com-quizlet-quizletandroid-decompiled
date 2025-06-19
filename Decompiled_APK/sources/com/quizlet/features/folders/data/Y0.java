package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class Y0 {
    public final String a;
    public final String b;

    public Y0(String folderTitle, String folderDescription) {
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        Intrinsics.checkNotNullParameter(folderDescription, "folderDescription");
        this.a = folderTitle;
        this.b = folderDescription;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Y0)) {
            return false;
        }
        Y0 y0 = (Y0) obj;
        return Intrinsics.b(this.a, y0.a) && Intrinsics.b(this.b, y0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UpdatedFolderUiData(folderTitle=");
        sb.append(this.a);
        sb.append(", folderDescription=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
