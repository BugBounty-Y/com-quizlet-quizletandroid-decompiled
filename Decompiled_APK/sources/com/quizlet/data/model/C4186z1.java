package com.quizlet.data.model;

import com.quizlet.generated.enums.EnumC4484g1;
import com.quizlet.generated.enums.EnumC4490i1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.z1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4186z1 {
    public final EnumC4484g1 a;
    public final com.quizlet.generated.enums.Y0 b;
    public final EnumC4490i1 c;

    public C4186z1(EnumC4484g1 numTermsFilter, com.quizlet.generated.enums.Y0 creatorTypeFilter, EnumC4490i1 contentTypeFilter) {
        Intrinsics.checkNotNullParameter(numTermsFilter, "numTermsFilter");
        Intrinsics.checkNotNullParameter(creatorTypeFilter, "creatorTypeFilter");
        Intrinsics.checkNotNullParameter(contentTypeFilter, "contentTypeFilter");
        this.a = numTermsFilter;
        this.b = creatorTypeFilter;
        this.c = contentTypeFilter;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4186z1)) {
            return false;
        }
        C4186z1 c4186z1 = (C4186z1) obj;
        return this.a == c4186z1.a && this.b == c4186z1.b && this.c == c4186z1.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "SearchFilters(numTermsFilter=" + this.a + ", creatorTypeFilter=" + this.b + ", contentTypeFilter=" + this.c + ")";
    }
}
