package com.quizlet.richtext.model;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PmParagraph {
    public final List a;
    public final String b;
    public final List c;

    public PmParagraph(String type, List list) {
        Intrinsics.checkNotNullParameter(type, "type");
        List blocks = list == null ? K.a : list;
        Intrinsics.checkNotNullParameter(blocks, "blocks");
        this.a = blocks;
        this.b = type;
        this.c = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PmParagraph)) {
            return false;
        }
        PmParagraph pmParagraph = (PmParagraph) obj;
        return Intrinsics.b(this.b, pmParagraph.b) && Intrinsics.b(this.c, pmParagraph.c);
    }

    public final int hashCode() {
        int iHashCode = this.b.hashCode() * 31;
        List list = this.c;
        return iHashCode + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        return "PmParagraph(type=" + this.b + ", content=" + this.c + ")";
    }
}
