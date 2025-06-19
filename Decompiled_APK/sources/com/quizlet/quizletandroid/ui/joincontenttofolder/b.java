package com.quizlet.quizletandroid.ui.joincontenttofolder;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends g {
    public final long a;
    public final LinkedHashSet b;
    public final ArrayList c;

    public b(long j, LinkedHashSet newFolderIds, ArrayList oldFolderIds) {
        Intrinsics.checkNotNullParameter(newFolderIds, "newFolderIds");
        Intrinsics.checkNotNullParameter(oldFolderIds, "oldFolderIds");
        this.a = j;
        this.b = newFolderIds;
        this.c = oldFolderIds;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        bVar.getClass();
        return this.a == bVar.a && Intrinsics.b(this.b, bVar.b) && Intrinsics.b(this.c, bVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + d0.d(Integer.hashCode(-1) * 31, 31, this.a)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ClassFinishedSuccessfully(resultCode=-1, classId=");
        sb.append(this.a);
        sb.append(", newFolderIds=");
        sb.append(this.b);
        sb.append(", oldFolderIds=");
        return AbstractC0147y.f(")", sb, this.c);
    }
}
