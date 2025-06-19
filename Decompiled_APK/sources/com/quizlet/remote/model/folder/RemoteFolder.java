package com.quizlet.remote.model.folder;

import androidx.compose.animation.d0;
import com.quizlet.db.data.models.persisted.fields.DBFolderFields;
import com.quizlet.remote.model.course.RemoteCourse;
import com.quizlet.remote.model.school.RemoteSchool;
import com.squareup.moshi.InterfaceC4853h;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteFolder {
    public final Long a;
    public final Long b;
    public final Long c;
    public final String d;
    public final String e;
    public final Long f;
    public final Boolean g;
    public final String h;
    public final boolean i;
    public final Long j;
    public final Long k;
    public final boolean l;
    public final Long m;
    public final Integer n;
    public final Boolean o;
    public final String p;
    public final String q;
    public final Integer r;
    public final RemoteCourse s;
    public final RemoteSchool t;

    public RemoteFolder(Long l, @InterfaceC4853h(name = "clientId") Long l2, Long l3, String str, String str2, Long l4, Boolean bool, String str3, boolean z, Long l5, Long l6, boolean z2, @InterfaceC4853h(name = DBFolderFields.Names.NUM_SETS) Long l7, @InterfaceC4853h(name = "_numStudyMaterials") Integer num, Boolean bool2, String str4, String str5, Integer num2, @InterfaceC4853h(ignore = true) RemoteCourse remoteCourse, @InterfaceC4853h(ignore = true) RemoteSchool remoteSchool) {
        this.a = l;
        this.b = l2;
        this.c = l3;
        this.d = str;
        this.e = str2;
        this.f = l4;
        this.g = bool;
        this.h = str3;
        this.i = z;
        this.j = l5;
        this.k = l6;
        this.l = z2;
        this.m = l7;
        this.n = num;
        this.o = bool2;
        this.p = str4;
        this.q = str5;
        this.r = num2;
        this.s = remoteCourse;
        this.t = remoteSchool;
    }

    public static /* synthetic */ RemoteFolder a(RemoteFolder remoteFolder, Long l, RemoteCourse remoteCourse, RemoteSchool remoteSchool, int i) {
        Integer num;
        RemoteCourse remoteCourse2;
        Long l2 = remoteFolder.a;
        Long l3 = (i & 2) != 0 ? remoteFolder.b : l;
        Long l4 = remoteFolder.c;
        String str = remoteFolder.d;
        String str2 = remoteFolder.e;
        Long l5 = remoteFolder.f;
        Boolean bool = remoteFolder.g;
        String str3 = remoteFolder.h;
        boolean z = remoteFolder.i;
        Long l6 = remoteFolder.j;
        Long l7 = remoteFolder.k;
        boolean z2 = remoteFolder.l;
        Long l8 = remoteFolder.m;
        Integer num2 = remoteFolder.n;
        Boolean bool2 = remoteFolder.o;
        String str4 = remoteFolder.p;
        String str5 = remoteFolder.q;
        Integer num3 = remoteFolder.r;
        if ((i & 262144) != 0) {
            num = num3;
            remoteCourse2 = remoteFolder.s;
        } else {
            num = num3;
            remoteCourse2 = remoteCourse;
        }
        return remoteFolder.copy(l2, l3, l4, str, str2, l5, bool, str3, z, l6, l7, z2, l8, num2, bool2, str4, str5, num, remoteCourse2, (i & 524288) != 0 ? remoteFolder.t : remoteSchool);
    }

    @NotNull
    public final RemoteFolder copy(Long l, @InterfaceC4853h(name = "clientId") Long l2, Long l3, String str, String str2, Long l4, Boolean bool, String str3, boolean z, Long l5, Long l6, boolean z2, @InterfaceC4853h(name = DBFolderFields.Names.NUM_SETS) Long l7, @InterfaceC4853h(name = "_numStudyMaterials") Integer num, Boolean bool2, String str4, String str5, Integer num2, @InterfaceC4853h(ignore = true) RemoteCourse remoteCourse, @InterfaceC4853h(ignore = true) RemoteSchool remoteSchool) {
        return new RemoteFolder(l, l2, l3, str, str2, l4, bool, str3, z, l5, l6, z2, l7, num, bool2, str4, str5, num2, remoteCourse, remoteSchool);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteFolder)) {
            return false;
        }
        RemoteFolder remoteFolder = (RemoteFolder) obj;
        return Intrinsics.b(this.a, remoteFolder.a) && Intrinsics.b(this.b, remoteFolder.b) && Intrinsics.b(this.c, remoteFolder.c) && Intrinsics.b(this.d, remoteFolder.d) && Intrinsics.b(this.e, remoteFolder.e) && Intrinsics.b(this.f, remoteFolder.f) && Intrinsics.b(this.g, remoteFolder.g) && Intrinsics.b(this.h, remoteFolder.h) && this.i == remoteFolder.i && Intrinsics.b(this.j, remoteFolder.j) && Intrinsics.b(this.k, remoteFolder.k) && this.l == remoteFolder.l && Intrinsics.b(this.m, remoteFolder.m) && Intrinsics.b(this.n, remoteFolder.n) && Intrinsics.b(this.o, remoteFolder.o) && Intrinsics.b(this.p, remoteFolder.p) && Intrinsics.b(this.q, remoteFolder.q) && Intrinsics.b(this.r, remoteFolder.r) && Intrinsics.b(this.s, remoteFolder.s) && Intrinsics.b(this.t, remoteFolder.t);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
        Long l2 = this.b;
        int iHashCode2 = (iHashCode + (l2 == null ? 0 : l2.hashCode())) * 31;
        Long l3 = this.c;
        int iHashCode3 = (iHashCode2 + (l3 == null ? 0 : l3.hashCode())) * 31;
        String str = this.d;
        int iHashCode4 = (iHashCode3 + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.e;
        int iHashCode5 = (iHashCode4 + (str2 == null ? 0 : str2.hashCode())) * 31;
        Long l4 = this.f;
        int iHashCode6 = (iHashCode5 + (l4 == null ? 0 : l4.hashCode())) * 31;
        Boolean bool = this.g;
        int iHashCode7 = (iHashCode6 + (bool == null ? 0 : bool.hashCode())) * 31;
        String str3 = this.h;
        int iG = d0.g((iHashCode7 + (str3 == null ? 0 : str3.hashCode())) * 31, 31, this.i);
        Long l5 = this.j;
        int iHashCode8 = (iG + (l5 == null ? 0 : l5.hashCode())) * 31;
        Long l6 = this.k;
        int iG2 = d0.g((iHashCode8 + (l6 == null ? 0 : l6.hashCode())) * 31, 31, this.l);
        Long l7 = this.m;
        int iHashCode9 = (iG2 + (l7 == null ? 0 : l7.hashCode())) * 31;
        Integer num = this.n;
        int iHashCode10 = (iHashCode9 + (num == null ? 0 : num.hashCode())) * 31;
        Boolean bool2 = this.o;
        int iHashCode11 = (iHashCode10 + (bool2 == null ? 0 : bool2.hashCode())) * 31;
        String str4 = this.p;
        int iHashCode12 = (iHashCode11 + (str4 == null ? 0 : str4.hashCode())) * 31;
        String str5 = this.q;
        int iHashCode13 = (iHashCode12 + (str5 == null ? 0 : str5.hashCode())) * 31;
        Integer num2 = this.r;
        int iHashCode14 = (iHashCode13 + (num2 == null ? 0 : num2.hashCode())) * 31;
        RemoteCourse remoteCourse = this.s;
        int iHashCode15 = (iHashCode14 + (remoteCourse == null ? 0 : remoteCourse.hashCode())) * 31;
        RemoteSchool remoteSchool = this.t;
        return iHashCode15 + (remoteSchool != null ? remoteSchool.hashCode() : 0);
    }

    public final String toString() {
        return "RemoteFolder(id=" + this.a + ", localId=" + this.b + ", personId=" + this.c + ", name=" + this.d + ", description=" + this.e + ", timestamp=" + this.f + ", isHidden=" + this.g + ", _webUrl=" + this.h + ", isDeleted=" + this.i + ", clientTimestamp=" + this.j + ", lastModified=" + this.k + ", isDirty=" + this.l + ", numSets=" + this.m + ", numStudyMaterials=" + this.n + ", isCoursePowered=" + this.o + ", courseName=" + this.p + ", schoolName=" + this.q + ", qpfGenerationMethod=" + this.r + ", course=" + this.s + ", school=" + this.t + ")";
    }

    public /* synthetic */ RemoteFolder(Long l, Long l2, Long l3, String str, String str2, Long l4, Boolean bool, String str3, boolean z, Long l5, Long l6, boolean z2, Long l7, Integer num, Boolean bool2, String str4, String str5, Integer num2, RemoteCourse remoteCourse, RemoteSchool remoteSchool, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(l, l2, l3, str, str2, l4, bool, str3, (i & 256) != 0 ? false : z, l5, l6, (i & 2048) != 0 ? false : z2, (i & 4096) != 0 ? null : l7, (i & 8192) != 0 ? null : num, (i & 16384) != 0 ? Boolean.FALSE : bool2, (32768 & i) != 0 ? null : str4, (65536 & i) != 0 ? null : str5, (131072 & i) != 0 ? null : num2, (262144 & i) != 0 ? null : remoteCourse, (i & 524288) != 0 ? null : remoteSchool);
    }
}
