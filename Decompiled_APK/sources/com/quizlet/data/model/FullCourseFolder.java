package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class FullCourseFolder extends J {
    public final com.quizlet.generated.enums.M0 A;
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
    public final Course x;
    public final School y;
    public final String z;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public FullCourseFolder(long j, boolean z, long j2, long j3, boolean z2, long j4, long j5, String name, boolean z3, String str, Long l, Course course, School school, String folderTypeLabel, com.quizlet.generated.enums.M0 qpfGenerationMethod) {
        super(j, z, j2, j3, z2, j4, name, str, j5, z3, school.i, l, folderTypeLabel);
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(course, "course");
        Intrinsics.checkNotNullParameter(school, "school");
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
        this.x = course;
        this.y = school;
        this.z = folderTypeLabel;
        this.A = qpfGenerationMethod;
    }

    public static FullCourseFolder n(FullCourseFolder fullCourseFolder, long j, String str, int i) {
        long j2 = fullCourseFolder.m;
        boolean z = fullCourseFolder.n;
        long j3 = fullCourseFolder.o;
        long j4 = (i & 8) != 0 ? fullCourseFolder.p : j;
        boolean z2 = (i & 16) != 0 ? fullCourseFolder.q : true;
        long j5 = j4;
        long j6 = fullCourseFolder.r;
        long j7 = fullCourseFolder.s;
        String name = (i & 128) != 0 ? fullCourseFolder.t : str;
        boolean z3 = fullCourseFolder.u;
        String str2 = fullCourseFolder.v;
        Long l = fullCourseFolder.w;
        Course course = fullCourseFolder.x;
        boolean z4 = z2;
        School school = fullCourseFolder.y;
        String folderTypeLabel = fullCourseFolder.z;
        com.quizlet.generated.enums.M0 qpfGenerationMethod = fullCourseFolder.A;
        fullCourseFolder.getClass();
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(course, "course");
        Intrinsics.checkNotNullParameter(school, "school");
        Intrinsics.checkNotNullParameter(folderTypeLabel, "folderTypeLabel");
        Intrinsics.checkNotNullParameter(qpfGenerationMethod, "qpfGenerationMethod");
        return new FullCourseFolder(j2, z, j3, j5, z4, j6, j7, name, z3, str2, l, course, school, folderTypeLabel, qpfGenerationMethod);
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
        if (!(obj instanceof FullCourseFolder)) {
            return false;
        }
        FullCourseFolder fullCourseFolder = (FullCourseFolder) obj;
        return this.m == fullCourseFolder.m && this.n == fullCourseFolder.n && this.o == fullCourseFolder.o && this.p == fullCourseFolder.p && this.q == fullCourseFolder.q && this.r == fullCourseFolder.r && this.s == fullCourseFolder.s && Intrinsics.b(this.t, fullCourseFolder.t) && this.u == fullCourseFolder.u && Intrinsics.b(this.v, fullCourseFolder.v) && Intrinsics.b(this.w, fullCourseFolder.w) && Intrinsics.b(this.x, fullCourseFolder.x) && Intrinsics.b(this.y, fullCourseFolder.y) && Intrinsics.b(this.z, fullCourseFolder.z) && this.A == fullCourseFolder.A;
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
        return this.A.hashCode() + androidx.compose.animation.d0.e((this.y.hashCode() + ((this.x.hashCode() + ((iHashCode + (l != null ? l.hashCode() : 0)) * 31)) * 31)) * 31, 31, this.z);
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
        return this.A;
    }

    public final String toString() {
        return "FullCourseFolder(id=" + this.m + ", isDeleted=" + this.n + ", lastModified=" + this.o + ", localId=" + this.p + ", isDirty=" + this.q + ", personId=" + this.r + ", timestamp=" + this.s + ", name=" + this.t + ", isHidden=" + this.u + ", webUrl=" + this.v + ", clientTimestamp=" + this.w + ", course=" + this.x + ", school=" + this.y + ", folderTypeLabel=" + this.z + ", qpfGenerationMethod=" + this.A + ")";
    }

    public /* synthetic */ FullCourseFolder(long j, boolean z, long j2, long j3, boolean z2, long j4, long j5, String str, boolean z3, String str2, Long l, Course course, School school, String str3, com.quizlet.generated.enums.M0 m0, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, z, j2, j3, z2, j4, j5, str, z3, str2, l, course, school, (i & 8192) != 0 ? "fullCourse" : str3, (i & 16384) != 0 ? com.quizlet.generated.enums.M0.NONE : m0);
    }
}
