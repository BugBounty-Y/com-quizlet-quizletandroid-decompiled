package com.quizlet.quizletandroid.ui.joincontenttofolder;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o extends g {
    public final ArrayList a;

    public o(ArrayList folderItems) {
        Intrinsics.checkNotNullParameter(folderItems, "folderItems");
        this.a = folderItems;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof o) && this.a.equals(((o) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return AbstractC0147y.f(")", new StringBuilder("ShowFolders(folderItems="), this.a);
    }
}
