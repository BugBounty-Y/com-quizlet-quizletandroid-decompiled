package com.quizlet.features.infra.folder;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final boolean b;
    public final boolean c;

    public a(String tabTitle, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(tabTitle, "tabTitle");
        this.a = tabTitle;
        this.b = z;
        this.c = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b && this.c == aVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + d0.g(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FolderTabData(tabTitle=");
        sb.append(this.a);
        sb.append(", plusTab=");
        sb.append(this.b);
        sb.append(", enabled=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
