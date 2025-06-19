package com.quizlet.quizletandroid.ui.library.data;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3674m5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3690o5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3698p5;
import com.quizlet.data.model.EnumC4164s0;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class J {
    public final List a;
    public final EnumC4164s0 b;
    public final AbstractC3698p5 c;
    public final AbstractC3690o5 d;
    public final AbstractC3674m5 e;
    public final boolean f;
    public final boolean g;
    public final boolean h;

    public J(List tabs, EnumC4164s0 startTab, AbstractC3698p5 studySetData, AbstractC3690o5 folderData, AbstractC3674m5 classesData, boolean z, boolean z2, boolean z3) {
        Intrinsics.checkNotNullParameter(tabs, "tabs");
        Intrinsics.checkNotNullParameter(startTab, "startTab");
        Intrinsics.checkNotNullParameter(studySetData, "studySetData");
        Intrinsics.checkNotNullParameter(folderData, "folderData");
        Intrinsics.checkNotNullParameter(classesData, "classesData");
        this.a = tabs;
        this.b = startTab;
        this.c = studySetData;
        this.d = folderData;
        this.e = classesData;
        this.f = z;
        this.g = z2;
        this.h = z3;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v11, types: [java.util.List] */
    public static J a(J j, ArrayList arrayList, EnumC4164s0 enumC4164s0, AbstractC3698p5 abstractC3698p5, AbstractC3690o5 abstractC3690o5, AbstractC3674m5 abstractC3674m5, boolean z, boolean z2, boolean z3, int i) {
        ArrayList arrayList2 = arrayList;
        if ((i & 1) != 0) {
            arrayList2 = j.a;
        }
        ArrayList tabs = arrayList2;
        if ((i & 2) != 0) {
            enumC4164s0 = j.b;
        }
        EnumC4164s0 startTab = enumC4164s0;
        if ((i & 4) != 0) {
            abstractC3698p5 = j.c;
        }
        AbstractC3698p5 studySetData = abstractC3698p5;
        if ((i & 8) != 0) {
            abstractC3690o5 = j.d;
        }
        AbstractC3690o5 folderData = abstractC3690o5;
        if ((i & 16) != 0) {
            abstractC3674m5 = j.e;
        }
        AbstractC3674m5 classesData = abstractC3674m5;
        if ((i & 32) != 0) {
            z = j.f;
        }
        boolean z4 = z;
        boolean z5 = (i & 64) != 0 ? j.g : z2;
        boolean z6 = (i & 128) != 0 ? j.h : z3;
        j.getClass();
        Intrinsics.checkNotNullParameter(tabs, "tabs");
        Intrinsics.checkNotNullParameter(startTab, "startTab");
        Intrinsics.checkNotNullParameter(studySetData, "studySetData");
        Intrinsics.checkNotNullParameter(folderData, "folderData");
        Intrinsics.checkNotNullParameter(classesData, "classesData");
        return new J(tabs, startTab, studySetData, folderData, classesData, z4, z5, z6);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof J)) {
            return false;
        }
        J j = (J) obj;
        return Intrinsics.b(this.a, j.a) && this.b == j.b && Intrinsics.b(this.c, j.c) && Intrinsics.b(this.d, j.d) && Intrinsics.b(this.e, j.e) && this.f == j.f && this.g == j.g && this.h == j.h;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.h) + d0.g(d0.g((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31, 31, this.f), 31, this.g);
    }

    public final String toString() {
        return "LibraryUiState(tabs=" + this.a + ", startTab=" + this.b + ", studySetData=" + this.c + ", folderData=" + this.d + ", classesData=" + this.e + ", canSeeClassFolderCreation=" + this.f + ", canSeePracticeTestCreation=" + this.g + ", isLibraryRedesignEnabled=" + this.h + ")";
    }
}
