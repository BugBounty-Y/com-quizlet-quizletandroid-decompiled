package com.quizlet.data.model.search;

import androidx.compose.animation.d0;
import com.quizlet.generated.enums.EnumC4497l;
import com.quizlet.generated.enums.W0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c {
    public final EnumC4497l a;
    public final String b;
    public final W0 c;
    public final String d;

    public c(EnumC4497l icon, String name, W0 type, String url) {
        Intrinsics.checkNotNullParameter(icon, "icon");
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(type, "type");
        Intrinsics.checkNotNullParameter(url, "url");
        this.a = icon;
        this.b = name;
        this.c = type;
        this.d = url;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && this.c == cVar.c && Intrinsics.b(this.d, cVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + ((this.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b)) * 31);
    }

    public final String toString() {
        return "SearchBannerModel(icon=" + this.a + ", name=" + this.b + ", type=" + this.c + ", url=" + this.d + ")";
    }
}
