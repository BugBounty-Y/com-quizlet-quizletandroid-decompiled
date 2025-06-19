package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class ContentFolder extends CreatedFolder {
    public final long l;
    public final boolean m;
    public final long n;
    public final long o;
    public final boolean p;
    public final long q;
    public final String r;
    public final String s;
    public final long t;
    public final boolean u;
    public final String v;
    public final Long w;
    public final Integer x;
    public final Integer y;
    public final String z;

    public /* synthetic */ ContentFolder(long j, boolean z, long j2, long j3, boolean z2, long j4, String str, String str2, long j5, boolean z3, String str3, Long l, Integer num, Integer num2, String str4, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(j, z, j2, j3, z2, j4, str, str2, j5, z3, str3, l, (i & 4096) != 0 ? null : num, (i & 8192) != 0 ? null : num2, (i & 16384) != 0 ? "created" : str4);
    }

    public static ContentFolder l(ContentFolder contentFolder, long j, String str, Integer num, int i) {
        long j2 = contentFolder.l;
        boolean z = contentFolder.m;
        long j3 = contentFolder.n;
        long j4 = (i & 8) != 0 ? contentFolder.o : j;
        boolean z2 = (i & 16) != 0 ? contentFolder.p : true;
        long j5 = j4;
        long j6 = contentFolder.q;
        String name = (i & 64) != 0 ? contentFolder.r : str;
        String description = contentFolder.s;
        long j7 = contentFolder.t;
        boolean z3 = contentFolder.u;
        String str2 = contentFolder.v;
        boolean z4 = z2;
        Long l = contentFolder.w;
        Integer num2 = (i & 4096) != 0 ? contentFolder.x : num;
        Integer num3 = contentFolder.y;
        String folderTypeLabel = contentFolder.z;
        contentFolder.getClass();
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(folderTypeLabel, "folderTypeLabel");
        return new ContentFolder(j2, z, j3, j5, z4, j6, name, description, j7, z3, str2, l, num2, num3, folderTypeLabel);
    }

    @Override // com.quizlet.data.model.CreatedFolder, com.quizlet.data.model.AbstractC4119d0
    public final long a() {
        return this.l;
    }

    @Override // com.quizlet.data.model.CreatedFolder, com.quizlet.data.model.AbstractC4119d0
    public final long b() {
        return this.n;
    }

    @Override // com.quizlet.data.model.CreatedFolder, com.quizlet.data.model.AbstractC4119d0
    public final long c() {
        return this.o;
    }

    @Override // com.quizlet.data.model.CreatedFolder, com.quizlet.data.model.AbstractC4119d0
    public final boolean d() {
        return this.m;
    }

    @Override // com.quizlet.data.model.CreatedFolder, com.quizlet.data.model.AbstractC4119d0
    public final boolean e() {
        return this.p;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ContentFolder)) {
            return false;
        }
        ContentFolder contentFolder = (ContentFolder) obj;
        return this.l == contentFolder.l && this.m == contentFolder.m && this.n == contentFolder.n && this.o == contentFolder.o && this.p == contentFolder.p && this.q == contentFolder.q && Intrinsics.b(this.r, contentFolder.r) && Intrinsics.b(this.s, contentFolder.s) && this.t == contentFolder.t && this.u == contentFolder.u && Intrinsics.b(this.v, contentFolder.v) && Intrinsics.b(this.w, contentFolder.w) && Intrinsics.b(this.x, contentFolder.x) && Intrinsics.b(this.y, contentFolder.y) && Intrinsics.b(this.z, contentFolder.z);
    }

    @Override // com.quizlet.data.model.CreatedFolder
    public final Long f() {
        return this.w;
    }

    @Override // com.quizlet.data.model.CreatedFolder
    public final String g() {
        return this.r;
    }

    @Override // com.quizlet.data.model.CreatedFolder
    public final long h() {
        return this.q;
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(androidx.compose.animation.d0.d(androidx.compose.animation.d0.e(androidx.compose.animation.d0.e(androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(androidx.compose.animation.d0.d(androidx.compose.animation.d0.d(androidx.compose.animation.d0.g(Long.hashCode(this.l) * 31, 31, this.m), 31, this.n), 31, this.o), 31, this.p), 31, this.q), 31, this.r), 31, this.s), 31, this.t), 31, this.u);
        String str = this.v;
        int iHashCode = (iG + (str == null ? 0 : str.hashCode())) * 31;
        Long l = this.w;
        int iHashCode2 = (iHashCode + (l == null ? 0 : l.hashCode())) * 31;
        Integer num = this.x;
        int iHashCode3 = (iHashCode2 + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.y;
        return this.z.hashCode() + ((iHashCode3 + (num2 != null ? num2.hashCode() : 0)) * 31);
    }

    @Override // com.quizlet.data.model.CreatedFolder
    public final long i() {
        return this.t;
    }

    @Override // com.quizlet.data.model.CreatedFolder
    public final String j() {
        return this.v;
    }

    @Override // com.quizlet.data.model.CreatedFolder
    public final boolean k() {
        return this.u;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ContentFolder(id=");
        sb.append(this.l);
        sb.append(", isDeleted=");
        sb.append(this.m);
        sb.append(", lastModified=");
        sb.append(this.n);
        sb.append(", localId=");
        sb.append(this.o);
        sb.append(", isDirty=");
        sb.append(this.p);
        sb.append(", personId=");
        sb.append(this.q);
        sb.append(", name=");
        sb.append(this.r);
        sb.append(", description=");
        sb.append(this.s);
        sb.append(", timestamp=");
        sb.append(this.t);
        sb.append(", isHidden=");
        sb.append(this.u);
        sb.append(", webUrl=");
        sb.append(this.v);
        sb.append(", clientTimestamp=");
        sb.append(this.w);
        sb.append(", numStudySets=");
        sb.append(this.x);
        sb.append(", numStudyMaterials=");
        sb.append(this.y);
        sb.append(", folderTypeLabel=");
        return android.support.v4.media.session.a.t(sb, this.z, ")");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ContentFolder(long j, boolean z, long j2, long j3, boolean z2, long j4, String name, String description, long j5, boolean z3, String str, Long l, Integer num, Integer num2, String folderTypeLabel) {
        super(j, z, j2, j3, z2, j4, name, description, j5, z3, str, l, folderTypeLabel, 0);
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(folderTypeLabel, "folderTypeLabel");
        this.l = j;
        this.m = z;
        this.n = j2;
        this.o = j3;
        this.p = z2;
        this.q = j4;
        this.r = name;
        this.s = description;
        this.t = j5;
        this.u = z3;
        this.v = str;
        this.w = l;
        this.x = num;
        this.y = num2;
        this.z = folderTypeLabel;
    }
}
