package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class SimpleImage {
    public final String a;
    public final Integer b;
    public final Integer c;
    public final boolean d;

    public SimpleImage(String srcUrl, Integer num, Integer num2) {
        Intrinsics.checkNotNullParameter(srcUrl, "srcUrl");
        this.a = srcUrl;
        this.b = num;
        this.c = num2;
        boolean z = false;
        if ((num2 != null ? num2.intValue() : 0) > 0) {
            if ((num != null ? num.intValue() : 0) > 0) {
                z = true;
            }
        }
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof SimpleImage)) {
            return false;
        }
        SimpleImage simpleImage = (SimpleImage) obj;
        return Intrinsics.b(this.a, simpleImage.a) && Intrinsics.b(this.b, simpleImage.b) && Intrinsics.b(this.c, simpleImage.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Integer num = this.b;
        int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.c;
        return iHashCode2 + (num2 != null ? num2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SimpleImage(srcUrl=");
        sb.append(this.a);
        sb.append(", height=");
        sb.append(this.b);
        sb.append(", width=");
        return assistantMode.refactored.a.l(sb, this.c, ")");
    }
}
