package io.ktor.http;

import java.util.List;
import java.util.Locale;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;

/* loaded from: classes3.dex */
public final class d extends androidx.appcompat.app.y {
    public static final d f = new d("*", "*", K.a);
    public final String d;
    public final String e;

    public d(String str, String str2, String str3, List list) {
        super(str3, list);
        this.d = str;
        this.e = str2;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        if (D.l(this.d, dVar.d, true) && D.l(this.e, dVar.e, true)) {
            return Intrinsics.b((List) this.c, (List) dVar.c);
        }
        return false;
    }

    public final int hashCode() {
        Locale locale = Locale.ROOT;
        String lowerCase = this.d.toLowerCase(locale);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "toLowerCase(...)");
        int iHashCode = lowerCase.hashCode();
        String lowerCase2 = this.e.toLowerCase(locale);
        Intrinsics.checkNotNullExpressionValue(lowerCase2, "toLowerCase(...)");
        return (((List) this.c).hashCode() * 31) + lowerCase2.hashCode() + (iHashCode * 31) + iHashCode;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public d(String contentType, String contentSubtype, List parameters) {
        this(contentType, contentSubtype, contentType + '/' + contentSubtype, parameters);
        Intrinsics.checkNotNullParameter(contentType, "contentType");
        Intrinsics.checkNotNullParameter(contentSubtype, "contentSubtype");
        Intrinsics.checkNotNullParameter(parameters, "parameters");
    }
}
