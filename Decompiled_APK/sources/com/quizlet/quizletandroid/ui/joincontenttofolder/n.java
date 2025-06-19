package com.quizlet.quizletandroid.ui.joincontenttofolder;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends g {
    public final Collection a;
    public final LinkedHashSet b;
    public final ArrayList c;

    public n(Collection setIds, LinkedHashSet newFolderIds, ArrayList oldFolderIds) {
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        Intrinsics.checkNotNullParameter(newFolderIds, "newFolderIds");
        Intrinsics.checkNotNullParameter(oldFolderIds, "oldFolderIds");
        this.a = setIds;
        this.b = newFolderIds;
        this.c = oldFolderIds;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        nVar.getClass();
        return Intrinsics.b(this.a, nVar.a) && Intrinsics.b(this.b, nVar.b) && this.c.equals(nVar.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + ((this.a.hashCode() + (Integer.hashCode(-1) * 31)) * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SetFinishedSuccessfully(resultCode=-1, setIds=");
        sb.append(this.a);
        sb.append(", newFolderIds=");
        sb.append(this.b);
        sb.append(", oldFolderIds=");
        return AbstractC0147y.f(")", sb, this.c);
    }
}
