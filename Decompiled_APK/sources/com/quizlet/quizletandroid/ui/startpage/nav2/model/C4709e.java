package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.startpage.nav2.model.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4709e extends AbstractC3603d6 {
    public final String a;
    public final boolean b;

    public C4709e(String sourceName, boolean z) {
        Intrinsics.checkNotNullParameter(sourceName, "sourceName");
        this.a = sourceName;
        this.b = z;
    }

    @Override // com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3603d6
    public final String c() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4709e)) {
            return false;
        }
        C4709e c4709e = (C4709e) obj;
        return Intrinsics.b(this.a, c4709e.a) && this.b == c4709e.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "CourseSourceRecommendation(sourceName=" + this.a + ", hasSchool=" + this.b + ")";
    }
}
