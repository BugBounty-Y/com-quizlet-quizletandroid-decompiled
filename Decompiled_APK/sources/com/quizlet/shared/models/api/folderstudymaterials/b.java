package com.quizlet.shared.models.api.folderstudymaterials;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final List a;
    public final List b;
    public final List c;
    public final List d;
    public final List e;
    public final List f;
    public final List g;
    public final List h;

    public b(List list, List list2, List list3, List list4, List list5, List list6, List list7, List list8) {
        this.a = list;
        this.b = list2;
        this.c = list3;
        this.d = list4;
        this.e = list5;
        this.f = list6;
        this.g = list7;
        this.h = list8;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b) && Intrinsics.b(this.c, bVar.c) && Intrinsics.b(this.d, bVar.d) && Intrinsics.b(this.e, bVar.e) && Intrinsics.b(this.f, bVar.f) && Intrinsics.b(this.g, bVar.g) && Intrinsics.b(this.h, bVar.h);
    }

    public final int hashCode() {
        List list = this.a;
        int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
        List list2 = this.b;
        int iHashCode2 = (iHashCode + (list2 == null ? 0 : list2.hashCode())) * 31;
        List list3 = this.c;
        int iHashCode3 = (iHashCode2 + (list3 == null ? 0 : list3.hashCode())) * 31;
        List list4 = this.d;
        int iHashCode4 = (iHashCode3 + (list4 == null ? 0 : list4.hashCode())) * 31;
        List list5 = this.e;
        int iHashCode5 = (iHashCode4 + (list5 == null ? 0 : list5.hashCode())) * 31;
        List list6 = this.f;
        int iHashCode6 = (iHashCode5 + (list6 == null ? 0 : list6.hashCode())) * 31;
        List list7 = this.g;
        int iHashCode7 = (iHashCode6 + (list7 == null ? 0 : list7.hashCode())) * 31;
        List list8 = this.h;
        return iHashCode7 + (list8 != null ? list8.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RemoteFolderStudyMaterialModel(folderStudyMaterials=");
        sb.append(this.a);
        sb.append(", users=");
        sb.append(this.b);
        sb.append(", studySets=");
        sb.append(this.c);
        sb.append(", folders=");
        sb.append(this.d);
        sb.append(", textbooks=");
        sb.append(this.e);
        sb.append(", textbookExercises=");
        sb.append(this.f);
        sb.append(", explanationQuestions=");
        sb.append(this.g);
        sb.append(", studyNotes=");
        return android.support.v4.media.session.a.n(")", sb, this.h);
    }
}
