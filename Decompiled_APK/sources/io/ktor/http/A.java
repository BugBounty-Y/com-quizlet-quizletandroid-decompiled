package io.ktor.http;

import java.util.ArrayList;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlin.text.StringsKt__StringsKt;

/* loaded from: classes3.dex */
public final class A {
    public final String a;
    public final int b;
    public final String c;
    public final String d;
    public final String e;
    public final y f;
    public final y g;
    public final kotlin.u h;
    public final kotlin.u i;

    public A(y yVar, String host, int i, ArrayList pathSegments, s parameters, String fragment, String str, String str2, String urlString) {
        Intrinsics.checkNotNullParameter(host, "host");
        Intrinsics.checkNotNullParameter(pathSegments, "pathSegments");
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        Intrinsics.checkNotNullParameter(fragment, "fragment");
        Intrinsics.checkNotNullParameter(urlString, "urlString");
        this.a = host;
        this.b = i;
        this.c = str;
        this.d = str2;
        this.e = urlString;
        if (i < 0 || i >= 65536) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Port must be between 0 and 65535, or 0 if not set. Provided: ").toString());
        }
        kotlin.l.b(new com.braze.communication.k(4, pathSegments));
        this.f = yVar;
        this.g = yVar == null ? y.c : yVar;
        kotlin.l.b(new com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.v(11, pathSegments, this));
        final int i2 = 0;
        kotlin.l.b(new Function0(this) { // from class: io.ktor.http.z
            public final /* synthetic */ A b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                A a = this.b;
                switch (i2) {
                    case 0:
                        int iL = StringsKt.L(a.e, '?', 0, false, 6) + 1;
                        if (iL == 0) {
                            return "";
                        }
                        String str3 = a.e;
                        int iL2 = StringsKt.L(str3, '#', iL, false, 4);
                        if (iL2 == -1) {
                            String strSubstring = str3.substring(iL);
                            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                            return strSubstring;
                        }
                        String strSubstring2 = str3.substring(iL, iL2);
                        Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                        return strSubstring2;
                    case 1:
                        int iL3 = StringsKt.L(a.e, '/', a.g.a.length() + 3, false, 4);
                        if (iL3 == -1) {
                            return "";
                        }
                        String str4 = a.e;
                        int iL4 = StringsKt.L(str4, '#', iL3, false, 4);
                        if (iL4 == -1) {
                            String strSubstring3 = str4.substring(iL3);
                            Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                            return strSubstring3;
                        }
                        String strSubstring4 = str4.substring(iL3, iL4);
                        Intrinsics.checkNotNullExpressionValue(strSubstring4, "substring(...)");
                        return strSubstring4;
                    case 2:
                        String str5 = a.c;
                        if (str5 == null) {
                            return null;
                        }
                        if (str5.length() == 0) {
                            return "";
                        }
                        int length = a.g.a.length() + 3;
                        String str6 = a.e;
                        String strSubstring5 = str6.substring(length, StringsKt__StringsKt.u(str6, new char[]{':', '@'}, length, false));
                        Intrinsics.checkNotNullExpressionValue(strSubstring5, "substring(...)");
                        return strSubstring5;
                    case 3:
                        String str7 = a.d;
                        if (str7 == null) {
                            return null;
                        }
                        if (str7.length() == 0) {
                            return "";
                        }
                        int length2 = a.g.a.length() + 3;
                        String str8 = a.e;
                        String strSubstring6 = str8.substring(StringsKt.L(str8, ':', length2, false, 4) + 1, StringsKt.L(str8, '@', 0, false, 6));
                        Intrinsics.checkNotNullExpressionValue(strSubstring6, "substring(...)");
                        return strSubstring6;
                    default:
                        int iL5 = StringsKt.L(a.e, '#', 0, false, 6) + 1;
                        if (iL5 == 0) {
                            return "";
                        }
                        String strSubstring7 = a.e.substring(iL5);
                        Intrinsics.checkNotNullExpressionValue(strSubstring7, "substring(...)");
                        return strSubstring7;
                }
            }
        });
        final int i3 = 1;
        kotlin.l.b(new Function0(this) { // from class: io.ktor.http.z
            public final /* synthetic */ A b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                A a = this.b;
                switch (i3) {
                    case 0:
                        int iL = StringsKt.L(a.e, '?', 0, false, 6) + 1;
                        if (iL == 0) {
                            return "";
                        }
                        String str3 = a.e;
                        int iL2 = StringsKt.L(str3, '#', iL, false, 4);
                        if (iL2 == -1) {
                            String strSubstring = str3.substring(iL);
                            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                            return strSubstring;
                        }
                        String strSubstring2 = str3.substring(iL, iL2);
                        Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                        return strSubstring2;
                    case 1:
                        int iL3 = StringsKt.L(a.e, '/', a.g.a.length() + 3, false, 4);
                        if (iL3 == -1) {
                            return "";
                        }
                        String str4 = a.e;
                        int iL4 = StringsKt.L(str4, '#', iL3, false, 4);
                        if (iL4 == -1) {
                            String strSubstring3 = str4.substring(iL3);
                            Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                            return strSubstring3;
                        }
                        String strSubstring4 = str4.substring(iL3, iL4);
                        Intrinsics.checkNotNullExpressionValue(strSubstring4, "substring(...)");
                        return strSubstring4;
                    case 2:
                        String str5 = a.c;
                        if (str5 == null) {
                            return null;
                        }
                        if (str5.length() == 0) {
                            return "";
                        }
                        int length = a.g.a.length() + 3;
                        String str6 = a.e;
                        String strSubstring5 = str6.substring(length, StringsKt__StringsKt.u(str6, new char[]{':', '@'}, length, false));
                        Intrinsics.checkNotNullExpressionValue(strSubstring5, "substring(...)");
                        return strSubstring5;
                    case 3:
                        String str7 = a.d;
                        if (str7 == null) {
                            return null;
                        }
                        if (str7.length() == 0) {
                            return "";
                        }
                        int length2 = a.g.a.length() + 3;
                        String str8 = a.e;
                        String strSubstring6 = str8.substring(StringsKt.L(str8, ':', length2, false, 4) + 1, StringsKt.L(str8, '@', 0, false, 6));
                        Intrinsics.checkNotNullExpressionValue(strSubstring6, "substring(...)");
                        return strSubstring6;
                    default:
                        int iL5 = StringsKt.L(a.e, '#', 0, false, 6) + 1;
                        if (iL5 == 0) {
                            return "";
                        }
                        String strSubstring7 = a.e.substring(iL5);
                        Intrinsics.checkNotNullExpressionValue(strSubstring7, "substring(...)");
                        return strSubstring7;
                }
            }
        });
        final int i4 = 2;
        this.h = kotlin.l.b(new Function0(this) { // from class: io.ktor.http.z
            public final /* synthetic */ A b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                A a = this.b;
                switch (i4) {
                    case 0:
                        int iL = StringsKt.L(a.e, '?', 0, false, 6) + 1;
                        if (iL == 0) {
                            return "";
                        }
                        String str3 = a.e;
                        int iL2 = StringsKt.L(str3, '#', iL, false, 4);
                        if (iL2 == -1) {
                            String strSubstring = str3.substring(iL);
                            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                            return strSubstring;
                        }
                        String strSubstring2 = str3.substring(iL, iL2);
                        Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                        return strSubstring2;
                    case 1:
                        int iL3 = StringsKt.L(a.e, '/', a.g.a.length() + 3, false, 4);
                        if (iL3 == -1) {
                            return "";
                        }
                        String str4 = a.e;
                        int iL4 = StringsKt.L(str4, '#', iL3, false, 4);
                        if (iL4 == -1) {
                            String strSubstring3 = str4.substring(iL3);
                            Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                            return strSubstring3;
                        }
                        String strSubstring4 = str4.substring(iL3, iL4);
                        Intrinsics.checkNotNullExpressionValue(strSubstring4, "substring(...)");
                        return strSubstring4;
                    case 2:
                        String str5 = a.c;
                        if (str5 == null) {
                            return null;
                        }
                        if (str5.length() == 0) {
                            return "";
                        }
                        int length = a.g.a.length() + 3;
                        String str6 = a.e;
                        String strSubstring5 = str6.substring(length, StringsKt__StringsKt.u(str6, new char[]{':', '@'}, length, false));
                        Intrinsics.checkNotNullExpressionValue(strSubstring5, "substring(...)");
                        return strSubstring5;
                    case 3:
                        String str7 = a.d;
                        if (str7 == null) {
                            return null;
                        }
                        if (str7.length() == 0) {
                            return "";
                        }
                        int length2 = a.g.a.length() + 3;
                        String str8 = a.e;
                        String strSubstring6 = str8.substring(StringsKt.L(str8, ':', length2, false, 4) + 1, StringsKt.L(str8, '@', 0, false, 6));
                        Intrinsics.checkNotNullExpressionValue(strSubstring6, "substring(...)");
                        return strSubstring6;
                    default:
                        int iL5 = StringsKt.L(a.e, '#', 0, false, 6) + 1;
                        if (iL5 == 0) {
                            return "";
                        }
                        String strSubstring7 = a.e.substring(iL5);
                        Intrinsics.checkNotNullExpressionValue(strSubstring7, "substring(...)");
                        return strSubstring7;
                }
            }
        });
        final int i5 = 3;
        this.i = kotlin.l.b(new Function0(this) { // from class: io.ktor.http.z
            public final /* synthetic */ A b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                A a = this.b;
                switch (i5) {
                    case 0:
                        int iL = StringsKt.L(a.e, '?', 0, false, 6) + 1;
                        if (iL == 0) {
                            return "";
                        }
                        String str3 = a.e;
                        int iL2 = StringsKt.L(str3, '#', iL, false, 4);
                        if (iL2 == -1) {
                            String strSubstring = str3.substring(iL);
                            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                            return strSubstring;
                        }
                        String strSubstring2 = str3.substring(iL, iL2);
                        Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                        return strSubstring2;
                    case 1:
                        int iL3 = StringsKt.L(a.e, '/', a.g.a.length() + 3, false, 4);
                        if (iL3 == -1) {
                            return "";
                        }
                        String str4 = a.e;
                        int iL4 = StringsKt.L(str4, '#', iL3, false, 4);
                        if (iL4 == -1) {
                            String strSubstring3 = str4.substring(iL3);
                            Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                            return strSubstring3;
                        }
                        String strSubstring4 = str4.substring(iL3, iL4);
                        Intrinsics.checkNotNullExpressionValue(strSubstring4, "substring(...)");
                        return strSubstring4;
                    case 2:
                        String str5 = a.c;
                        if (str5 == null) {
                            return null;
                        }
                        if (str5.length() == 0) {
                            return "";
                        }
                        int length = a.g.a.length() + 3;
                        String str6 = a.e;
                        String strSubstring5 = str6.substring(length, StringsKt__StringsKt.u(str6, new char[]{':', '@'}, length, false));
                        Intrinsics.checkNotNullExpressionValue(strSubstring5, "substring(...)");
                        return strSubstring5;
                    case 3:
                        String str7 = a.d;
                        if (str7 == null) {
                            return null;
                        }
                        if (str7.length() == 0) {
                            return "";
                        }
                        int length2 = a.g.a.length() + 3;
                        String str8 = a.e;
                        String strSubstring6 = str8.substring(StringsKt.L(str8, ':', length2, false, 4) + 1, StringsKt.L(str8, '@', 0, false, 6));
                        Intrinsics.checkNotNullExpressionValue(strSubstring6, "substring(...)");
                        return strSubstring6;
                    default:
                        int iL5 = StringsKt.L(a.e, '#', 0, false, 6) + 1;
                        if (iL5 == 0) {
                            return "";
                        }
                        String strSubstring7 = a.e.substring(iL5);
                        Intrinsics.checkNotNullExpressionValue(strSubstring7, "substring(...)");
                        return strSubstring7;
                }
            }
        });
        final int i6 = 4;
        kotlin.l.b(new Function0(this) { // from class: io.ktor.http.z
            public final /* synthetic */ A b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function0
            public final Object invoke() {
                A a = this.b;
                switch (i6) {
                    case 0:
                        int iL = StringsKt.L(a.e, '?', 0, false, 6) + 1;
                        if (iL == 0) {
                            return "";
                        }
                        String str3 = a.e;
                        int iL2 = StringsKt.L(str3, '#', iL, false, 4);
                        if (iL2 == -1) {
                            String strSubstring = str3.substring(iL);
                            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                            return strSubstring;
                        }
                        String strSubstring2 = str3.substring(iL, iL2);
                        Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                        return strSubstring2;
                    case 1:
                        int iL3 = StringsKt.L(a.e, '/', a.g.a.length() + 3, false, 4);
                        if (iL3 == -1) {
                            return "";
                        }
                        String str4 = a.e;
                        int iL4 = StringsKt.L(str4, '#', iL3, false, 4);
                        if (iL4 == -1) {
                            String strSubstring3 = str4.substring(iL3);
                            Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                            return strSubstring3;
                        }
                        String strSubstring4 = str4.substring(iL3, iL4);
                        Intrinsics.checkNotNullExpressionValue(strSubstring4, "substring(...)");
                        return strSubstring4;
                    case 2:
                        String str5 = a.c;
                        if (str5 == null) {
                            return null;
                        }
                        if (str5.length() == 0) {
                            return "";
                        }
                        int length = a.g.a.length() + 3;
                        String str6 = a.e;
                        String strSubstring5 = str6.substring(length, StringsKt__StringsKt.u(str6, new char[]{':', '@'}, length, false));
                        Intrinsics.checkNotNullExpressionValue(strSubstring5, "substring(...)");
                        return strSubstring5;
                    case 3:
                        String str7 = a.d;
                        if (str7 == null) {
                            return null;
                        }
                        if (str7.length() == 0) {
                            return "";
                        }
                        int length2 = a.g.a.length() + 3;
                        String str8 = a.e;
                        String strSubstring6 = str8.substring(StringsKt.L(str8, ':', length2, false, 4) + 1, StringsKt.L(str8, '@', 0, false, 6));
                        Intrinsics.checkNotNullExpressionValue(strSubstring6, "substring(...)");
                        return strSubstring6;
                    default:
                        int iL5 = StringsKt.L(a.e, '#', 0, false, 6) + 1;
                        if (iL5 == 0) {
                            return "";
                        }
                        String strSubstring7 = a.e.substring(iL5);
                        Intrinsics.checkNotNullExpressionValue(strSubstring7, "substring(...)");
                        return strSubstring7;
                }
            }
        });
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || A.class != obj.getClass()) {
            return false;
        }
        return Intrinsics.b(this.e, ((A) obj).e);
    }

    public final int hashCode() {
        return this.e.hashCode();
    }

    public final String toString() {
        return this.e;
    }
}
