package com.quizlet.data.model.search;

import androidx.compose.animation.d0;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final String a;
    public final String b;
    public final boolean c;
    public final String d;
    public final b e;

    public /* synthetic */ a(String str) {
        this(str, "", "", false);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c && Intrinsics.b(this.d, aVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.g(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MisspellingsResult(originalQuery=");
        sb.append(this.a);
        sb.append(", correctedQuery=");
        sb.append(this.b);
        sb.append(", isQueryCorrected=");
        sb.append(this.c);
        sb.append(", misspellingsMessage=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }

    public a(String originalQuery, String correctedQuery, String value, boolean z) {
        Object next;
        Intrinsics.checkNotNullParameter(originalQuery, "originalQuery");
        Intrinsics.checkNotNullParameter(correctedQuery, "correctedQuery");
        Intrinsics.checkNotNullParameter(value, "misspellingsMessage");
        this.a = originalQuery;
        this.b = correctedQuery;
        this.c = z;
        this.d = value;
        b.b.getClass();
        Intrinsics.checkNotNullParameter(value, "value");
        Iterator it2 = b.e.iterator();
        while (true) {
            if (!it2.hasNext()) {
                next = null;
                break;
            } else {
                next = it2.next();
                if (((b) next).a.equals(value)) {
                    break;
                }
            }
        }
        b bVar = (b) next;
        this.e = bVar == null ? b.c : bVar;
    }
}
