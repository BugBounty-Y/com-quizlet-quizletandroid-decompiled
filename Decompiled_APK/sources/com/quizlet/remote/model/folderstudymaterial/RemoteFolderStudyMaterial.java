package com.quizlet.remote.model.folderstudymaterial;

import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class RemoteFolderStudyMaterial {
    public final Long a;
    public final Long b;
    public final String c;
    public final Integer d;
    public final Long e;
    public final Long f;
    public final Long g;
    public final Long h;
    public final Boolean i;

    public RemoteFolderStudyMaterial(Long l, Long l2, String str, Integer num, Long l3, Long l4, Long l5, Long l6, Boolean bool) {
        this.a = l;
        this.b = l2;
        this.c = str;
        this.d = num;
        this.e = l3;
        this.f = l4;
        this.g = l5;
        this.h = l6;
        this.i = bool;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RemoteFolderStudyMaterial)) {
            return false;
        }
        RemoteFolderStudyMaterial remoteFolderStudyMaterial = (RemoteFolderStudyMaterial) obj;
        return Intrinsics.b(this.a, remoteFolderStudyMaterial.a) && Intrinsics.b(this.b, remoteFolderStudyMaterial.b) && Intrinsics.b(this.c, remoteFolderStudyMaterial.c) && Intrinsics.b(this.d, remoteFolderStudyMaterial.d) && Intrinsics.b(this.e, remoteFolderStudyMaterial.e) && Intrinsics.b(this.f, remoteFolderStudyMaterial.f) && Intrinsics.b(this.g, remoteFolderStudyMaterial.g) && Intrinsics.b(this.h, remoteFolderStudyMaterial.h) && Intrinsics.b(this.i, remoteFolderStudyMaterial.i);
    }

    public final int hashCode() {
        Long l = this.a;
        int iHashCode = (l == null ? 0 : l.hashCode()) * 31;
        Long l2 = this.b;
        int iHashCode2 = (iHashCode + (l2 == null ? 0 : l2.hashCode())) * 31;
        String str = this.c;
        int iHashCode3 = (iHashCode2 + (str == null ? 0 : str.hashCode())) * 31;
        Integer num = this.d;
        int iHashCode4 = (iHashCode3 + (num == null ? 0 : num.hashCode())) * 31;
        Long l3 = this.e;
        int iHashCode5 = (iHashCode4 + (l3 == null ? 0 : l3.hashCode())) * 31;
        Long l4 = this.f;
        int iHashCode6 = (iHashCode5 + (l4 == null ? 0 : l4.hashCode())) * 31;
        Long l5 = this.g;
        int iHashCode7 = (iHashCode6 + (l5 == null ? 0 : l5.hashCode())) * 31;
        Long l6 = this.h;
        int iHashCode8 = (iHashCode7 + (l6 == null ? 0 : l6.hashCode())) * 31;
        Boolean bool = this.i;
        return iHashCode8 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteFolderStudyMaterial(id=");
        sb.append(this.a);
        sb.append(", folderId=");
        sb.append(this.b);
        sb.append(", studyMaterialId=");
        sb.append(this.c);
        sb.append(", studyMaterialType=");
        sb.append(this.d);
        sb.append(", userId=");
        sb.append(this.e);
        sb.append(", subFolderId=");
        sb.append(this.f);
        sb.append(", timestamp=");
        sb.append(this.g);
        sb.append(", lastModified=");
        sb.append(this.h);
        sb.append(", isDeleted=");
        return assistantMode.refactored.a.k(sb, this.i, ")");
    }

    public /* synthetic */ RemoteFolderStudyMaterial(Long l, Long l2, String str, Integer num, Long l3, Long l4, Long l5, Long l6, Boolean bool, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this(l, l2, str, num, l3, l4, l5, l6, (i & 256) != 0 ? null : bool);
    }
}
