package assistantMode.types;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class k {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final String e;
    public final String f;
    public final String g;
    public final long h;
    public final long i;
    public final long j;
    public final long k;
    public final long l;
    public final long m;

    public k(String _legacyUrl, String _legacyUrlSmall, String _legacyUrlSquare, String _secureLegacyUrl, String _secureLegacyUrlSmall, String _secureLegacyUrlSquare, String code, long j, long j2, long j3, long j4, long j5, long j6) {
        Intrinsics.checkNotNullParameter(_legacyUrl, "_legacyUrl");
        Intrinsics.checkNotNullParameter(_legacyUrlSmall, "_legacyUrlSmall");
        Intrinsics.checkNotNullParameter(_legacyUrlSquare, "_legacyUrlSquare");
        Intrinsics.checkNotNullParameter(_secureLegacyUrl, "_secureLegacyUrl");
        Intrinsics.checkNotNullParameter(_secureLegacyUrlSmall, "_secureLegacyUrlSmall");
        Intrinsics.checkNotNullParameter(_secureLegacyUrlSquare, "_secureLegacyUrlSquare");
        Intrinsics.checkNotNullParameter(code, "code");
        Intrinsics.checkNotNullParameter("", "flickrOwner");
        this.a = _legacyUrl;
        this.b = _legacyUrlSmall;
        this.c = _legacyUrlSquare;
        this.d = _secureLegacyUrl;
        this.e = _secureLegacyUrlSmall;
        this.f = _secureLegacyUrlSquare;
        this.g = code;
        this.h = j;
        this.i = j2;
        this.j = j3;
        this.k = j4;
        this.l = j5;
        this.m = j6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return this.a.equals(kVar.a) && this.b.equals(kVar.b) && this.c.equals(kVar.c) && this.d.equals(kVar.d) && this.e.equals(kVar.e) && this.f.equals(kVar.f) && Intrinsics.b(this.g, kVar.g) && this.h == kVar.h && this.i == kVar.i && this.j == kVar.j && this.k == kVar.k && this.l == kVar.l && this.m == kVar.m;
    }

    public final int hashCode() {
        return Long.hashCode(this.m) + d0.d(d0.d(d0.d(d0.d(d0.d(d0.d(d0.d(d0.e(d0.e(d0.e(d0.e(d0.e(d0.e(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d), 31, this.e), 31, this.f), 31, this.g), 961, -1L), 31, this.h), 31, this.i), 31, this.j), 31, -1L), 31, this.k), 31, this.l);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Image(_legacyUrl=");
        sb.append(this.a);
        sb.append(", _legacyUrlSmall=");
        sb.append(this.b);
        sb.append(", _legacyUrlSquare=");
        sb.append(this.c);
        sb.append(", _secureLegacyUrl=");
        sb.append(this.d);
        sb.append(", _secureLegacyUrlSmall=");
        sb.append(this.e);
        sb.append(", _secureLegacyUrlSquare=");
        sb.append(this.f);
        sb.append(", code=");
        sb.append(this.g);
        sb.append(", flickrId=-1, flickrOwner=, height=");
        sb.append(this.h);
        sb.append(", id=");
        sb.append(this.i);
        sb.append(", lastModified=");
        sb.append(this.j);
        sb.append(", license=-1, personId=");
        sb.append(this.k);
        sb.append(", timestamp=");
        sb.append(this.l);
        sb.append(", width=");
        return android.support.v4.media.session.a.g(this.m, ")", sb);
    }
}
