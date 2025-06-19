package com.quizlet.features.folders.logging;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.y1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final long a;
    public final String b;
    public final y1 c;
    public final boolean d;
    public final Integer e;
    public final String f;
    public final boolean g;

    public f(long j, String str, y1 y1Var, boolean z, Integer num, String str2, int i) {
        z = (i & 8) != 0 ? false : z;
        num = (i & 32) != 0 ? null : num;
        str2 = (i & 64) != 0 ? null : str2;
        boolean z2 = (i & 128) == 0;
        this.a = j;
        this.b = str;
        this.c = y1Var;
        this.d = z;
        this.e = num;
        this.f = str2;
        this.g = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && Intrinsics.b(this.b, fVar.b) && this.c == fVar.c && this.d == fVar.d && Intrinsics.b(this.e, fVar.e) && Intrinsics.b(this.f, fVar.f) && this.g == fVar.g;
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        y1 y1Var = this.c;
        int iG = d0.g(d0.g((iHashCode2 + (y1Var == null ? 0 : y1Var.hashCode())) * 31, 31, this.d), 31, false);
        Integer num = this.e;
        int iHashCode3 = (iG + (num == null ? 0 : num.hashCode())) * 31;
        String str2 = this.f;
        return Boolean.hashCode(this.g) + ((iHashCode3 + (str2 != null ? str2.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LoggingMaterialData(folderId=");
        sb.append(this.a);
        sb.append(", studyMaterialId=");
        sb.append(this.b);
        sb.append(", studyMaterialType=");
        sb.append(this.c);
        sb.append(", isCourseRecommendation=");
        sb.append(this.d);
        sb.append(", isCoursePoweredFolder=false, itemPosition=");
        sb.append(this.e);
        sb.append(", tagName=");
        sb.append(this.f);
        sb.append(", isFromAddMaterialToFolder=");
        return android.support.v4.media.session.a.o(")", sb, this.g);
    }
}
