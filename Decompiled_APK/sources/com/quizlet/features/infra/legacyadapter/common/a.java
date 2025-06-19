package com.quizlet.features.infra.legacyadapter.common;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final boolean a;
    public final Integer b;
    public final Integer c;
    public final Integer d;
    public final Integer e;
    public final Integer f;
    public final Integer g;

    public a(boolean z, Integer num, Integer num2, Integer num3, Integer num4, Integer num5, Integer num6) {
        this.a = z;
        this.b = num;
        this.c = num2;
        this.d = num3;
        this.e = num4;
        this.f = num5;
        this.g = num6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d) && Intrinsics.b(this.e, aVar.e) && Intrinsics.b(this.f, aVar.f) && Intrinsics.b(this.g, aVar.g);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        Integer num = this.b;
        int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.c;
        int iHashCode3 = (iHashCode2 + (num2 == null ? 0 : num2.hashCode())) * 31;
        Integer num3 = this.d;
        int iHashCode4 = (iHashCode3 + (num3 == null ? 0 : num3.hashCode())) * 31;
        Integer num4 = this.e;
        int iHashCode5 = (iHashCode4 + (num4 == null ? 0 : num4.hashCode())) * 31;
        Integer num5 = this.f;
        int iHashCode6 = (iHashCode5 + (num5 == null ? 0 : num5.hashCode())) * 31;
        Integer num6 = this.g;
        return iHashCode6 + (num6 != null ? num6.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UserListTitleAttributeData(isLargeView=");
        sb.append(this.a);
        sb.append(", profileImageSizeRes=");
        sb.append(this.b);
        sb.append(", usernameTextStyleRes=");
        sb.append(this.c);
        sb.append(", badgeTextStyleRes=");
        sb.append(this.d);
        sb.append(", verifiedIconSizeRes=");
        sb.append(this.e);
        sb.append(", usernameMarginStartRes=");
        sb.append(this.f);
        sb.append(", badgeMarginStartRes=");
        return assistantMode.refactored.a.l(sb, this.g, ")");
    }
}
