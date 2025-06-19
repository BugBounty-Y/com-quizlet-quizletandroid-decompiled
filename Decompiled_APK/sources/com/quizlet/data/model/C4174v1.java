package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.data.model.v1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4174v1 {
    public final List a;
    public final Object b;
    public final List c;
    public final Object d;

    public C4174v1(List createRequest, Object obj, List deleteRequest, Object obj2) {
        Intrinsics.checkNotNullParameter(createRequest, "createRequest");
        Intrinsics.checkNotNullParameter(deleteRequest, "deleteRequest");
        this.a = createRequest;
        this.b = obj;
        this.c = deleteRequest;
        this.d = obj2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4174v1)) {
            return false;
        }
        C4174v1 c4174v1 = (C4174v1) obj;
        if (!Intrinsics.b(this.a, c4174v1.a)) {
            return false;
        }
        kotlin.p pVar = kotlin.r.b;
        return Intrinsics.b(this.b, c4174v1.b) && Intrinsics.b(this.c, c4174v1.c) && Intrinsics.b(this.d, c4174v1.d);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        kotlin.p pVar = kotlin.r.b;
        Object obj = this.b;
        int iF = androidx.compose.animation.d0.f(((obj == null ? 0 : obj.hashCode()) + iHashCode) * 31, 31, this.c);
        Object obj2 = this.d;
        return (obj2 != null ? obj2.hashCode() : 0) + iF;
    }

    public final String toString() {
        return "SaveStudyMaterialToFolderResult(createRequest=" + this.a + ", created=" + kotlin.r.b(this.b) + ", deleteRequest=" + this.c + ", deleted=" + kotlin.r.b(this.d) + ")";
    }
}
