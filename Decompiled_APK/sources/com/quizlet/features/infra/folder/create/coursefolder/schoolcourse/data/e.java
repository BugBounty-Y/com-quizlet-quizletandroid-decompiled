package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends f {
    public final long f;
    public final String g;
    public final String h;
    public final d i;
    public final boolean j;
    public final String k;

    public /* synthetic */ e(long j, String str, String str2, String str3, int i) {
        this(j, str, str2, (i & 8) != 0 ? d.b : d.a, false, (i & 32) != 0 ? "" : str3);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.f == eVar.f && Intrinsics.b(this.g, eVar.g) && Intrinsics.b(this.h, eVar.h) && this.i == eVar.i && this.j == eVar.j && Intrinsics.b(this.k, eVar.k);
    }

    public final int hashCode() {
        return this.k.hashCode() + d0.g((this.i.hashCode() + d0.e(d0.e(Long.hashCode(this.f) * 31, 31, this.g), 31, this.h)) * 31, 31, this.j);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("School(schoolId=");
        sb.append(this.f);
        sb.append(", schoolTitle=");
        sb.append(this.g);
        sb.append(", schoolDescription=");
        sb.append(this.h);
        sb.append(", schoolType=");
        sb.append(this.i);
        sb.append(", savingSchool=");
        sb.append(this.j);
        sb.append(", schoolSearchSessionId=");
        return android.support.v4.media.session.a.t(sb, this.k, ")");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(long j, String schoolTitle, String schoolDescription, d schoolType, boolean z, String schoolSearchSessionId) {
        super(j, schoolTitle, schoolDescription, z, schoolSearchSessionId);
        Intrinsics.checkNotNullParameter(schoolTitle, "schoolTitle");
        Intrinsics.checkNotNullParameter(schoolDescription, "schoolDescription");
        Intrinsics.checkNotNullParameter(schoolType, "schoolType");
        Intrinsics.checkNotNullParameter(schoolSearchSessionId, "schoolSearchSessionId");
        this.f = j;
        this.g = schoolTitle;
        this.h = schoolDescription;
        this.i = schoolType;
        this.j = z;
        this.k = schoolSearchSessionId;
    }
}
