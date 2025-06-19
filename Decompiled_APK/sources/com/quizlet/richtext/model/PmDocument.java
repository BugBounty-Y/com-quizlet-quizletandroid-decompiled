package com.quizlet.richtext.model;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PmDocument {
    public final List a;
    public final String b;
    public final List c;

    public PmDocument(String type, List paragraphs) {
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(paragraphs, "content");
        Intrinsics.checkNotNullParameter(paragraphs, "paragraphs");
        this.a = paragraphs;
        this.b = type;
        this.c = paragraphs;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PmDocument)) {
            return false;
        }
        PmDocument pmDocument = (PmDocument) obj;
        return Intrinsics.b(this.b, pmDocument.b) && Intrinsics.b(this.c, pmDocument.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + (this.b.hashCode() * 31);
    }

    public final String toString() {
        return "PmDocument(type=" + this.b + ", content=" + this.c + ")";
    }
}
