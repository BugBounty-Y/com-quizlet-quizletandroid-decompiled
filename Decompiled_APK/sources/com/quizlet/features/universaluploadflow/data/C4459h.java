package com.quizlet.features.universaluploadflow.data;

import com.quizlet.data.model.m2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.universaluploadflow.data.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4459h {
    public final boolean a;
    public final m2 b;

    public C4459h(boolean z, m2 source) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter("", "initialText");
        this.a = z;
        this.b = source;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4459h)) {
            return false;
        }
        C4459h c4459h = (C4459h) obj;
        return this.a == c4459h.a && this.b == c4459h.b;
    }

    public final int hashCode() {
        return (this.b.hashCode() + (Boolean.hashCode(this.a) * 31)) * 961;
    }

    public final String toString() {
        return "PasteTextNavigationData(isPublic=" + this.a + ", source=" + this.b + ", initialText=, addMaterialFolderData=null)";
    }
}
