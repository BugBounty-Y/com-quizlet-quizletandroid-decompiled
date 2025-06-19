package com.quizlet.shared.models.explanations;

import androidx.compose.animation.d0;
import assistantMode.refactored.a;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.AbstractC5047c0;
import org.jetbrains.annotations.NotNull;
import serialization.e;

@f
@Metadata
/* loaded from: classes3.dex */
public final class Textbook extends e {

    @NotNull
    public static final Companion Companion = new Companion();
    public final long b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final boolean h;
    public final String i;
    public final int j;
    public final boolean k;
    public final String l;
    public final Boolean m;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return Textbook$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ Textbook(int i, long j, String str, String str2, String str3, String str4, String str5, boolean z, String str6, int i2, boolean z2, String str7, Boolean bool) {
        if (2047 != (i & 2047)) {
            AbstractC5047c0.k(i, 2047, Textbook$$serializer.INSTANCE.getDescriptor());
            throw null;
        }
        this.b = j;
        this.c = str;
        this.d = str2;
        this.e = str3;
        this.f = str4;
        this.g = str5;
        this.h = z;
        this.i = str6;
        this.j = i2;
        this.k = z2;
        this.l = str7;
        if ((i & 2048) == 0) {
            this.m = null;
        } else {
            this.m = bool;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Textbook)) {
            return false;
        }
        Textbook textbook = (Textbook) obj;
        return this.b == textbook.b && Intrinsics.b(this.c, textbook.c) && Intrinsics.b(this.d, textbook.d) && Intrinsics.b(this.e, textbook.e) && Intrinsics.b(this.f, textbook.f) && Intrinsics.b(this.g, textbook.g) && this.h == textbook.h && Intrinsics.b(this.i, textbook.i) && this.j == textbook.j && this.k == textbook.k && Intrinsics.b(this.l, textbook.l) && Intrinsics.b(this.m, textbook.m);
    }

    public final int hashCode() {
        int iE = d0.e(d0.e(d0.e(Long.hashCode(this.b) * 31, 31, this.c), 31, this.d), 31, this.e);
        String str = this.f;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.g;
        int iG = d0.g(d0.b(this.j, d0.e(d0.g((iHashCode + (str2 == null ? 0 : str2.hashCode())) * 31, 31, this.h), 31, this.i), 31), 31, this.k);
        String str3 = this.l;
        int iHashCode2 = (iG + (str3 == null ? 0 : str3.hashCode())) * 31;
        Boolean bool = this.m;
        return iHashCode2 + (bool != null ? bool.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Textbook(id=");
        sb.append(this.b);
        sb.append(", isbn=");
        sb.append(this.c);
        sb.append(", title=");
        sb.append(this.d);
        sb.append(", authors=");
        sb.append(this.e);
        sb.append(", imageUrl=");
        sb.append(this.f);
        sb.append(", imageThumbnailUrl=");
        sb.append(this.g);
        sb.append(", isPremium=");
        sb.append(this.h);
        sb.append(", edition=");
        sb.append(this.i);
        sb.append(", verifiedSolutionCount=");
        sb.append(this.j);
        sb.append(", hasSolutions=");
        sb.append(this.k);
        sb.append(", webUrl=");
        sb.append(this.l);
        sb.append(", isDeleted=");
        return a.k(sb, this.m, ")");
    }
}
