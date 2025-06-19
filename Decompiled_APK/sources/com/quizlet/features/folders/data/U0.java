package com.quizlet.features.folders.data;

import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class U0 implements W0 {
    public final kotlinx.collections.immutable.b a;
    public final int b;
    public final boolean c;
    public final boolean d;
    public final boolean e;

    public U0(kotlinx.collections.immutable.b subFoldersUiData, int i, boolean z, boolean z2, boolean z3) {
        Intrinsics.checkNotNullParameter(subFoldersUiData, "subFoldersUiData");
        this.a = subFoldersUiData;
        this.b = i;
        this.c = z;
        this.d = z2;
        this.e = z3;
    }

    @Override // com.quizlet.features.folders.data.W0
    public final kotlinx.collections.immutable.b a() {
        return this.a;
    }

    @Override // com.quizlet.features.folders.data.W0
    public final boolean b() {
        return this.c;
    }

    @Override // com.quizlet.features.folders.data.W0
    public final int c() {
        return this.b;
    }

    @Override // com.quizlet.features.folders.data.W0
    public final String d() {
        String str;
        com.quizlet.features.infra.models.folders.c cVar = (com.quizlet.features.infra.models.folders.c) CollectionsKt.O(c(), a());
        return (cVar == null || (str = cVar.c) == null) ? "" : str;
    }

    @Override // com.quizlet.features.folders.data.W0
    public final boolean e() {
        return this.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof U0)) {
            return false;
        }
        U0 u0 = (U0) obj;
        return Intrinsics.b(this.a, u0.a) && this.b == u0.b && this.c == u0.c && this.d == u0.d && this.e == u0.e;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + androidx.compose.animation.d0.g(androidx.compose.animation.d0.g(androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31), 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(subFoldersUiData=");
        sb.append(this.a);
        sb.append(", selectedTabIndex=");
        sb.append(this.b);
        sb.append(", canAddTags=");
        sb.append(this.c);
        sb.append(", canAddNewTags=");
        sb.append(this.d);
        sb.append(", shouldShowAddTagTooltip=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
