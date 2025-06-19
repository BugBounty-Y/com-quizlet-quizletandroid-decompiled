package com.quizlet.shared.models.api.notes;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;

@kotlinx.serialization.f
@Metadata
/* loaded from: classes3.dex */
public final class ReviewSheetSection {

    @NotNull
    public static final Companion Companion = new Companion();
    public final String a;
    public final String b;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return ReviewSheetSection$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ ReviewSheetSection(int i, String str, String str2) {
        if (3 != (i & 3)) {
            AbstractC5047c0.k(i, 3, ReviewSheetSection$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.a = str;
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ReviewSheetSection)) {
            return false;
        }
        ReviewSheetSection reviewSheetSection = (ReviewSheetSection) obj;
        return Intrinsics.b(this.a, reviewSheetSection.a) && Intrinsics.b(this.b, reviewSheetSection.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ReviewSheetSection(content=");
        sb.append(this.a);
        sb.append(", title=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
