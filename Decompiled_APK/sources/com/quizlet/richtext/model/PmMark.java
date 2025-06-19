package com.quizlet.richtext.model;

import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PmMark {
    public final String a;
    public final String b;
    public final PmAttribute c;

    public PmMark(@NotNull String markType, @InterfaceC4853h(name = "attrs") PmAttribute pmAttribute) {
        Intrinsics.checkNotNullParameter(markType, "type");
        Intrinsics.checkNotNullParameter(markType, "markType");
        this.a = markType;
        this.b = markType;
        this.c = pmAttribute;
    }

    @NotNull
    public final PmMark copy(@NotNull String type, @InterfaceC4853h(name = "attrs") PmAttribute pmAttribute) {
        Intrinsics.checkNotNullParameter(type, "type");
        return new PmMark(type, pmAttribute);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PmMark)) {
            return false;
        }
        PmMark pmMark = (PmMark) obj;
        return Intrinsics.b(this.b, pmMark.b) && Intrinsics.b(this.c, pmMark.c);
    }

    public final int hashCode() {
        int iHashCode = this.b.hashCode() * 31;
        PmAttribute pmAttribute = this.c;
        return iHashCode + (pmAttribute == null ? 0 : pmAttribute.a.hashCode());
    }

    public final String toString() {
        return "PmMark(type=" + this.b + ", attr=" + this.c + ")";
    }
}
