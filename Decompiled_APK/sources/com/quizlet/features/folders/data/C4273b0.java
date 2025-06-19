package com.quizlet.features.folders.data;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.b0, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4273b0 implements InterfaceC4289j0 {
    public final long a;
    public final ArrayList b;

    public C4273b0(long j, ArrayList currentFolderTags) {
        Intrinsics.checkNotNullParameter(currentFolderTags, "currentFolderTags");
        this.a = j;
        this.b = currentFolderTags;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4273b0)) {
            return false;
        }
        C4273b0 c4273b0 = (C4273b0) obj;
        return this.a == c4273b0.a && this.b.equals(c4273b0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GoToAddSubFolder(parentFolderId=");
        sb.append(this.a);
        sb.append(", currentFolderTags=");
        return AbstractC0147y.f(")", sb, this.b);
    }
}
