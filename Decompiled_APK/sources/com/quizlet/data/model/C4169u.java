package com.quizlet.data.model;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.u, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4169u {
    public final long a;
    public final String b;
    public final boolean c;
    public final ArrayList d;

    public C4169u(long j, String folderTitle, boolean z, ArrayList arrayList) {
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        this.a = j;
        this.b = folderTitle;
        this.c = z;
        this.d = arrayList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4169u)) {
            return false;
        }
        C4169u c4169u = (C4169u) obj;
        return this.a == c4169u.a && Intrinsics.b(this.b, c4169u.b) && this.c == c4169u.c && Intrinsics.b(this.d, c4169u.d);
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(androidx.compose.animation.d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
        ArrayList arrayList = this.d;
        return iG + (arrayList == null ? 0 : arrayList.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AddStudyMaterialFolderData(folderId=");
        sb.append(this.a);
        sb.append(", folderTitle=");
        sb.append(this.b);
        sb.append(", isStudyMaterialAlreadyAdded=");
        sb.append(this.c);
        sb.append(", subfolders=");
        return AbstractC0147y.f(")", sb, this.d);
    }
}
