package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class BasicCourseFolder extends J {
    public final long m;
    public final boolean n;
    public final long o;
    public final long p;
    public final boolean q;
    public final long r;
    public final long s;
    public final String t;
    public final boolean u;
    public final String v;
    public final Long w;
    public final String x;
    public final String y;
    public final com.quizlet.generated.enums.M0 z;

    public /* synthetic */ BasicCourseFolder(long j, boolean z, long j2, long j3, boolean z2, long j4, long j5, String str, boolean z3, String str2, Long l, String str3, String str4, com.quizlet.generated.enums.M0 m0, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, z, j2, j3, z2, j4, j5, str, z3, str2, l, str3, (i & 4096) != 0 ? "basicCourse" : str4, (i & 8192) != 0 ? com.quizlet.generated.enums.M0.NONE : m0);
    }

    public static BasicCourseFolder n(BasicCourseFolder basicCourseFolder, long j, String str, int i) {
        long j2 = basicCourseFolder.m;
        boolean z = basicCourseFolder.n;
        long j3 = basicCourseFolder.o;
        long j4 = (i & 8) != 0 ? basicCourseFolder.p : j;
        boolean z2 = (i & 16) != 0 ? basicCourseFolder.q : true;
        long j5 = j4;
        long j6 = basicCourseFolder.r;
        long j7 = basicCourseFolder.s;
        String name = (i & 128) != 0 ? basicCourseFolder.t : str;
        boolean z3 = basicCourseFolder.u;
        String str2 = basicCourseFolder.v;
        Long l = basicCourseFolder.w;
        String schoolCourseDescription = basicCourseFolder.x;
        boolean z4 = z2;
        String folderTypeLabel = basicCourseFolder.y;
        com.quizlet.generated.enums.M0 qpfGenerationMethod = basicCourseFolder.z;
        basicCourseFolder.getClass();
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(schoolCourseDescription, "schoolCourseDescription");
        Intrinsics.checkNotNullParameter(folderTypeLabel, "folderTypeLabel");
        Intrinsics.checkNotNullParameter(qpfGenerationMethod, "qpfGenerationMethod");
        return new BasicCourseFolder(j2, z, j3, j5, z4, j6, j7, name, z3, str2, l, schoolCourseDescription, folderTypeLabel, qpfGenerationMethod);
    }

    @Override // com.quizlet.data.model.CreatedFolder, com.quizlet.data.model.AbstractC4119d0
    public final long a() {
        return this.m;
    }

    @Override // com.quizlet.data.model.CreatedFolder, com.quizlet.data.model.AbstractC4119d0
    public final long b() {
        return this.o;
    }

    @Override // com.quizlet.data.model.CreatedFolder, com.quizlet.data.model.AbstractC4119d0
    public final long c() {
        return this.p;
    }

    @Override // com.quizlet.data.model.CreatedFolder, com.quizlet.data.model.AbstractC4119d0
    public final boolean d() {
        return this.n;
    }

    @Override // com.quizlet.data.model.CreatedFolder, com.quizlet.data.model.AbstractC4119d0
    public final boolean e() {
        return this.q;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof BasicCourseFolder)) {
            return false;
        }
        BasicCourseFolder basicCourseFolder = (BasicCourseFolder) obj;
        return this.m == basicCourseFolder.m && this.n == basicCourseFolder.n && this.o == basicCourseFolder.o && this.p == basicCourseFolder.p && this.q == basicCourseFolder.q && this.r == basicCourseFolder.r && this.s == basicCourseFolder.s && Intrinsics.b(this.t, basicCourseFolder.t) && this.u == basicCourseFolder.u && Intrinsics.b(this.v, basicCourseFolder.v) && Intrinsics.b(this.w, basicCourseFolder.w) && Intrinsics.b(this.x, basicCourseFolder.x) && Intrinsics.b(this.y, basicCourseFolder.y) && this.z == basicCourseFolder.z;
    }

    @Override // com.quizlet.data.model.J, com.quizlet.data.model.CreatedFolder
    public final Long f() {
        return this.w;
    }

    @Override // com.quizlet.data.model.J, com.quizlet.data.model.CreatedFolder
    public final String g() {
        return this.t;
    }

    @Override // com.quizlet.data.model.J, com.quizlet.data.model.CreatedFolder
    public final long h() {
        return this.r;
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(androidx.compose.animation.d0.e(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(Long.hashCode(this.m) * 31, 31, this.n), 31, this.o), 31, this.p), 31, this.q), 31, this.r), 31, this.s), 31, this.t), 31, this.u);
        String str = this.v;
        int iHashCode = (iG + (str == null ? 0 : str.hashCode())) * 31;
        Long l = this.w;
        return this.z.hashCode() + androidx.compose.animation.d0.e(androidx.compose.animation.d0.e((iHashCode + (l != null ? l.hashCode() : 0)) * 31, 31, this.x), 31, this.y);
    }

    @Override // com.quizlet.data.model.J, com.quizlet.data.model.CreatedFolder
    public final long i() {
        return this.s;
    }

    @Override // com.quizlet.data.model.J, com.quizlet.data.model.CreatedFolder
    public final String j() {
        return this.v;
    }

    @Override // com.quizlet.data.model.J, com.quizlet.data.model.CreatedFolder
    public final boolean k() {
        return this.u;
    }

    @Override // com.quizlet.data.model.J
    public final com.quizlet.generated.enums.M0 l() {
        return this.z;
    }

    @Override // com.quizlet.data.model.J
    public final String m() {
        return this.x;
    }

    public final String toString() {
        return "BasicCourseFolder(id=" + this.m + ", isDeleted=" + this.n + ", lastModified=" + this.o + ", localId=" + this.p + ", isDirty=" + this.q + ", personId=" + this.r + ", timestamp=" + this.s + ", name=" + this.t + ", isHidden=" + this.u + ", webUrl=" + this.v + ", clientTimestamp=" + this.w + ", schoolCourseDescription=" + this.x + ", folderTypeLabel=" + this.y + ", qpfGenerationMethod=" + this.z + ")";
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BasicCourseFolder(long j, boolean z, long j2, long j3, boolean z2, long j4, long j5, String name, boolean z3, String str, Long l, String schoolCourseDescription, String folderTypeLabel, com.quizlet.generated.enums.M0 qpfGenerationMethod) {
        super(j, z, j2, j3, z2, j4, name, str, j5, z3, schoolCourseDescription, l, folderTypeLabel);
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(schoolCourseDescription, "schoolCourseDescription");
        Intrinsics.checkNotNullParameter(folderTypeLabel, "folderTypeLabel");
        Intrinsics.checkNotNullParameter(qpfGenerationMethod, "qpfGenerationMethod");
        this.m = j;
        this.n = z;
        this.o = j2;
        this.p = j3;
        this.q = z2;
        this.r = j4;
        this.s = j5;
        this.t = name;
        this.u = z3;
        this.v = str;
        this.w = l;
        this.x = schoolCourseDescription;
        this.y = folderTypeLabel;
        this.z = qpfGenerationMethod;
    }
}
