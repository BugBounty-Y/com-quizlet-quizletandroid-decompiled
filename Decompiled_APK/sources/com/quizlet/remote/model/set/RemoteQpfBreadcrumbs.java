package com.quizlet.remote.model.set;

import com.quizlet.db.data.models.persisted.fields.DBGroupFields;
import com.squareup.moshi.InterfaceC4853h;
import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteQpfBreadcrumbs {
    public final String a;
    public final String b;
    public final Long c;
    public final String d;
    public final Long e;
    public final Long f;

    public RemoteQpfBreadcrumbs(@InterfaceC4853h(name = "courseCode") String str, @InterfaceC4853h(name = "folderLinkPath") String str2, @InterfaceC4853h(name = "folderId") Long l, @InterfaceC4853h(name = "schoolName") String str3, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) Long l2, @InterfaceC4853h(name = "courseId") Long l3) {
        this.a = str;
        this.b = str2;
        this.c = l;
        this.d = str3;
        this.e = l2;
        this.f = l3;
    }

    @NotNull
    public final RemoteQpfBreadcrumbs copy(@InterfaceC4853h(name = "courseCode") String str, @InterfaceC4853h(name = "folderLinkPath") String str2, @InterfaceC4853h(name = "folderId") Long l, @InterfaceC4853h(name = "schoolName") String str3, @InterfaceC4853h(name = DBGroupFields.Names.SCHOOL_ID) Long l2, @InterfaceC4853h(name = "courseId") Long l3) {
        return new RemoteQpfBreadcrumbs(str, str2, l, str3, l2, l3);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteQpfBreadcrumbs)) {
            return false;
        }
        RemoteQpfBreadcrumbs remoteQpfBreadcrumbs = (RemoteQpfBreadcrumbs) obj;
        return Intrinsics.b(this.a, remoteQpfBreadcrumbs.a) && Intrinsics.b(this.b, remoteQpfBreadcrumbs.b) && Intrinsics.b(this.c, remoteQpfBreadcrumbs.c) && Intrinsics.b(this.d, remoteQpfBreadcrumbs.d) && Intrinsics.b(this.e, remoteQpfBreadcrumbs.e) && Intrinsics.b(this.f, remoteQpfBreadcrumbs.f);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        int iHashCode2 = (iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31;
        Long l = this.c;
        int iHashCode3 = (iHashCode2 + (l == null ? 0 : l.hashCode())) * 31;
        String str3 = this.d;
        int iHashCode4 = (iHashCode3 + (str3 == null ? 0 : str3.hashCode())) * 31;
        Long l2 = this.e;
        int iHashCode5 = (iHashCode4 + (l2 == null ? 0 : l2.hashCode())) * 31;
        Long l3 = this.f;
        return iHashCode5 + (l3 != null ? l3.hashCode() : 0);
    }

    public final String toString() {
        return "RemoteQpfBreadcrumbs(courseCode=" + this.a + ", folderLinkPath=" + this.b + ", folderId=" + this.c + ", schoolName=" + this.d + ", schoolId=" + this.e + ", courseId=" + this.f + ")";
    }
}
