package com.quizlet.features.infra.folder.create.coursefolder.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements m {
    public final String a;
    public final boolean b;
    public final String c;
    public final boolean d;
    public final String e;
    public final boolean f;

    public k(String schoolTitle, boolean z, String courseTitle, boolean z2, String folderTitle, boolean z3) {
        Intrinsics.checkNotNullParameter(schoolTitle, "schoolTitle");
        Intrinsics.checkNotNullParameter(courseTitle, "courseTitle");
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        this.a = schoolTitle;
        this.b = z;
        this.c = courseTitle;
        this.d = z2;
        this.e = folderTitle;
        this.f = z3;
    }

    public static k d(k kVar, String str, boolean z, String str2, String folderTitle, boolean z2, int i) {
        if ((i & 1) != 0) {
            str = kVar.a;
        }
        String schoolTitle = str;
        if ((i & 2) != 0) {
            z = kVar.b;
        }
        boolean z3 = z;
        if ((i & 4) != 0) {
            str2 = kVar.c;
        }
        String courseTitle = str2;
        if ((i & 32) != 0) {
            z2 = kVar.f;
        }
        Intrinsics.checkNotNullParameter(schoolTitle, "schoolTitle");
        Intrinsics.checkNotNullParameter(courseTitle, "courseTitle");
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        return new k(schoolTitle, z3, courseTitle, kVar.d, folderTitle, z2);
    }

    @Override // com.quizlet.features.infra.folder.create.coursefolder.data.m
    public final boolean a() {
        return this.f;
    }

    @Override // com.quizlet.features.infra.folder.create.coursefolder.data.m
    public final boolean b() {
        return this.d;
    }

    @Override // com.quizlet.features.infra.folder.create.coursefolder.data.m
    public final String c() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Intrinsics.b(this.a, kVar.a) && this.b == kVar.b && Intrinsics.b(this.c, kVar.c) && this.d == kVar.d && Intrinsics.b(this.e, kVar.e) && this.f == kVar.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + d0.e(d0.g(d0.e(d0.g(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e);
    }

    public final String toString() {
        return "Loaded(schoolTitle=" + this.a + ", isCourseFolder=" + this.b + ", courseTitle=" + this.c + ", canMakeAsCourseFolder=" + this.d + ", folderTitle=" + this.e + ", isSaveButtonEnabled=" + this.f + ")";
    }
}
