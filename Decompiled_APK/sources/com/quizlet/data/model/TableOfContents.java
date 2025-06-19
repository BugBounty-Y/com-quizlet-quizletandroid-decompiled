package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class TableOfContents {
    public static final kotlin.collections.K b;
    public final List a;

    static {
        kotlin.collections.K items = kotlin.collections.K.a;
        Intrinsics.checkNotNullParameter(items, "items");
        b = items;
    }

    public final boolean equals(Object obj) {
        if (obj instanceof TableOfContents) {
            return Intrinsics.b(this.a, ((TableOfContents) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "TableOfContents(items=" + this.a + ")";
    }
}
