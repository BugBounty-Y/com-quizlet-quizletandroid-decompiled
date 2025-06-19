package com.quizlet.shared.models.api.notes;

import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements b {
    public final ArrayList a;
    public final boolean b;

    public a(ArrayList files, boolean z) {
        Intrinsics.checkNotNullParameter(files, "files");
        this.a = files;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Files(files=");
        sb.append(this.a);
        sb.append(", isPrivate=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
