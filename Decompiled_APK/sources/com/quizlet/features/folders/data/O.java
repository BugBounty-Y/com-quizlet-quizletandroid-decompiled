package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class O implements T {
    public final Object a;

    public O(Object obj) {
        this.a = obj;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof O)) {
            return false;
        }
        Object obj2 = ((O) obj).a;
        kotlin.p pVar = kotlin.r.b;
        return Intrinsics.b(this.a, obj2);
    }

    public final int hashCode() {
        kotlin.p pVar = kotlin.r.b;
        Object obj = this.a;
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("TagsChanged(folderDataResult=", kotlin.r.b(this.a), ")");
    }
}
