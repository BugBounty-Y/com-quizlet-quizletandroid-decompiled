package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class Q0 {
    public final String a;
    public final String b;
    public final Integer c;
    public final String d;
    public final long e;
    public final String f;
    public final String g;
    public final boolean h;
    public final boolean i;
    public final boolean j;
    public final R0 k;
    public final boolean l;
    public final boolean m;
    public final EnumC4270a n;
    public final boolean o;
    public final com.quizlet.features.infra.folder.create.data.i p;
    public final long q;
    public final boolean r;
    public final com.quizlet.generated.enums.M0 s;

    public Q0(String folderTitle, String folderDescription, Integer num, String str, long j, String str2, String webUrl, boolean z, boolean z2, boolean z3, R0 r0, boolean z4, boolean z5, EnumC4270a copyFolderState, boolean z6, com.quizlet.features.infra.folder.create.data.i iVar, long j2, boolean z7, com.quizlet.generated.enums.M0 qpfGenerationMethod) {
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        Intrinsics.checkNotNullParameter(folderDescription, "folderDescription");
        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
        Intrinsics.checkNotNullParameter(copyFolderState, "copyFolderState");
        Intrinsics.checkNotNullParameter(qpfGenerationMethod, "qpfGenerationMethod");
        this.a = folderTitle;
        this.b = folderDescription;
        this.c = num;
        this.d = str;
        this.e = j;
        this.f = str2;
        this.g = webUrl;
        this.h = z;
        this.i = z2;
        this.j = z3;
        this.k = r0;
        this.l = z4;
        this.m = z5;
        this.n = copyFolderState;
        this.o = z6;
        this.p = iVar;
        this.q = j2;
        this.r = z7;
        this.s = qpfGenerationMethod;
    }

    public static Q0 a(Q0 q0, String str, String str2, boolean z, EnumC4270a enumC4270a, long j, int i) {
        boolean z2;
        long j2;
        String folderTitle = (i & 1) != 0 ? q0.a : str;
        String folderDescription = (i & 2) != 0 ? q0.b : str2;
        Integer num = q0.c;
        String str3 = q0.d;
        long j3 = q0.e;
        q0.getClass();
        String str4 = q0.f;
        String webUrl = q0.g;
        boolean z3 = (i & 256) != 0 ? q0.h : false;
        boolean z4 = q0.i;
        boolean z5 = q0.j;
        R0 r0 = q0.k;
        boolean z6 = (i & 4096) != 0 ? q0.l : z;
        boolean z7 = q0.m;
        EnumC4270a copyFolderState = (i & 16384) != 0 ? q0.n : enumC4270a;
        boolean z8 = q0.o;
        com.quizlet.features.infra.folder.create.data.i iVar = q0.p;
        if ((i & 131072) != 0) {
            z2 = z7;
            j2 = q0.q;
        } else {
            z2 = z7;
            j2 = j;
        }
        boolean z9 = q0.r;
        com.quizlet.generated.enums.M0 qpfGenerationMethod = q0.s;
        q0.getClass();
        Intrinsics.checkNotNullParameter(folderTitle, "folderTitle");
        Intrinsics.checkNotNullParameter(folderDescription, "folderDescription");
        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
        Intrinsics.checkNotNullParameter(copyFolderState, "copyFolderState");
        Intrinsics.checkNotNullParameter(qpfGenerationMethod, "qpfGenerationMethod");
        return new Q0(folderTitle, folderDescription, num, str3, j3, str4, webUrl, z3, z4, z5, r0, z6, z2, copyFolderState, z8, iVar, j2, z9, qpfGenerationMethod);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Q0)) {
            return false;
        }
        Q0 q0 = (Q0) obj;
        return Intrinsics.b(this.a, q0.a) && Intrinsics.b(this.b, q0.b) && Intrinsics.b(this.c, q0.c) && Intrinsics.b(this.d, q0.d) && this.e == q0.e && Intrinsics.b(this.f, q0.f) && Intrinsics.b(this.g, q0.g) && this.h == q0.h && this.i == q0.i && this.j == q0.j && Intrinsics.b(this.k, q0.k) && this.l == q0.l && this.m == q0.m && this.n == q0.n && this.o == q0.o && Intrinsics.b(this.p, q0.p) && this.q == q0.q && this.r == q0.r && this.s == q0.s;
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b);
        Integer num = this.c;
        int iHashCode = (iE + (num == null ? 0 : num.hashCode())) * 31;
        String str = this.d;
        int iG = androidx.compose.animation.d0.g(androidx.compose.animation.d0.d((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.e), 31, false);
        String str2 = this.f;
        int iG2 = androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.e((iG + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.g), 31, this.h), 31, this.i), 31, this.j);
        R0 r0 = this.k;
        int iG3 = androidx.compose.animation.d0.g((this.n.hashCode() + androidx.compose.animation.d0.g(androidx.compose.animation.d0.g((iG2 + (r0 == null ? 0 : r0.hashCode())) * 31, 31, this.l), 31, this.m)) * 31, 31, this.o);
        com.quizlet.features.infra.folder.create.data.i iVar = this.p;
        return this.s.hashCode() + androidx.compose.animation.d0.g(androidx.compose.animation.d0.d((iG3 + (iVar != null ? iVar.hashCode() : 0)) * 31, 31, this.q), 31, this.r);
    }

    public final String toString() {
        return "FolderUiData(folderTitle=" + this.a + ", folderDescription=" + this.b + ", itemsCount=" + this.c + ", folderCreatorName=" + this.d + ", creatorId=" + this.e + ", creatorUnderAge=false, creatorImageUrl=" + this.f + ", webUrl=" + this.g + ", canRemoveContent=" + this.h + ", isCoursePowered=" + this.i + ", canShowRecs=" + this.j + ", modifiedUiData=" + this.k + ", shouldShowAddNewMenu=" + this.l + ", isPublicFolder=" + this.m + ", copyFolderState=" + this.n + ", shouldSeeQpfTooltip=" + this.o + ", schoolCourseUiData=" + this.p + ", folderId=" + this.q + ", isSubfolderFeatureEnabled=" + this.r + ", qpfGenerationMethod=" + this.s + ")";
    }
}
