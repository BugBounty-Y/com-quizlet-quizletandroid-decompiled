package okhttp3;

import androidx.recyclerview.widget.C1372j;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class s {
    public static final char[] k = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final int e;
    public final ArrayList f;
    public final ArrayList g;
    public final String h;
    public final String i;
    public final boolean j;

    public s(String scheme, String username, String password, String host, int i, ArrayList pathSegments, ArrayList arrayList, String str, String url) {
        Intrinsics.checkNotNullParameter(scheme, "scheme");
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(password, "password");
        Intrinsics.checkNotNullParameter(host, "host");
        Intrinsics.checkNotNullParameter(pathSegments, "pathSegments");
        Intrinsics.checkNotNullParameter(url, "url");
        this.a = scheme;
        this.b = username;
        this.c = password;
        this.d = host;
        this.e = i;
        this.f = pathSegments;
        this.g = arrayList;
        this.h = str;
        this.i = url;
        this.j = Intrinsics.b(scheme, "https");
    }

    public final String a() {
        if (this.c.length() == 0) {
            return "";
        }
        int length = this.a.length() + 3;
        String str = this.i;
        String strSubstring = str.substring(StringsKt.L(str, ':', length, false, 4) + 1, StringsKt.L(str, '@', 0, false, 6));
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        return strSubstring;
    }

    public final String b() {
        int length = this.a.length() + 3;
        String str = this.i;
        int iL = StringsKt.L(str, '/', length, false, 4);
        String strSubstring = str.substring(iL, okhttp3.internal.b.g(str, iL, "?#", str.length()));
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        return strSubstring;
    }

    public final ArrayList c() {
        int length = this.a.length() + 3;
        String str = this.i;
        int iL = StringsKt.L(str, '/', length, false, 4);
        int iG = okhttp3.internal.b.g(str, iL, "?#", str.length());
        ArrayList arrayList = new ArrayList();
        while (iL < iG) {
            int i = iL + 1;
            int iF = okhttp3.internal.b.f(str, '/', i, iG);
            String strSubstring = str.substring(i, iF);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
            arrayList.add(strSubstring);
            iL = iF;
        }
        return arrayList;
    }

    public final String d() {
        if (this.g == null) {
            return null;
        }
        String str = this.i;
        int iL = StringsKt.L(str, '?', 0, false, 6) + 1;
        String strSubstring = str.substring(iL, okhttp3.internal.b.f(str, '#', iL, str.length()));
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        return strSubstring;
    }

    public final String e() {
        if (this.b.length() == 0) {
            return "";
        }
        int length = this.a.length() + 3;
        String str = this.i;
        String strSubstring = str.substring(length, okhttp3.internal.b.g(str, length, ":@", str.length()));
        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
        return strSubstring;
    }

    public final boolean equals(Object obj) {
        return (obj instanceof s) && Intrinsics.b(((s) obj).i, this.i);
    }

    public final C1372j f() {
        String strSubstring;
        C1372j c1372j = new C1372j();
        String scheme = this.a;
        c1372j.e = scheme;
        String strE = e();
        Intrinsics.checkNotNullParameter(strE, "<set-?>");
        c1372j.f = strE;
        String strA = a();
        Intrinsics.checkNotNullParameter(strA, "<set-?>");
        c1372j.g = strA;
        c1372j.h = this.d;
        Intrinsics.checkNotNullParameter(scheme, "scheme");
        int i = Intrinsics.b(scheme, "http") ? 80 : Intrinsics.b(scheme, "https") ? 443 : -1;
        int i2 = this.e;
        c1372j.b = i2 != i ? i2 : -1;
        ArrayList arrayList = c1372j.c;
        arrayList.clear();
        arrayList.addAll(c());
        c1372j.h(d());
        if (this.h == null) {
            strSubstring = null;
        } else {
            String str = this.i;
            strSubstring = str.substring(StringsKt.L(str, '#', 0, false, 6) + 1);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String).substring(startIndex)");
        }
        c1372j.i = strSubstring;
        return c1372j;
    }

    public final C1372j g(String link) {
        Intrinsics.checkNotNullParameter(link, "link");
        try {
            C1372j c1372j = new C1372j();
            c1372j.l(this, link);
            return c1372j;
        } catch (IllegalArgumentException unused) {
            return null;
        }
    }

    public final String h() {
        C1372j c1372jG = g("/...");
        Intrinsics.d(c1372jG);
        Intrinsics.checkNotNullParameter("", "username");
        c1372jG.f = o.b(0, 0, 251, "", " \"':;<=>@[]^`{}|/\\?#", false);
        Intrinsics.checkNotNullParameter("", DBStudySetFields.Names.PASSWORD);
        c1372jG.g = o.b(0, 0, 251, "", " \"':;<=>@[]^`{}|/\\?#", false);
        return c1372jG.d().i;
    }

    public final int hashCode() {
        return this.i.hashCode();
    }

    public final s i(String link) {
        Intrinsics.checkNotNullParameter(link, "link");
        C1372j c1372jG = g(link);
        if (c1372jG != null) {
            return c1372jG.d();
        }
        return null;
    }

    public final URI j() {
        C1372j c1372jF = f();
        String str = (String) c1372jF.h;
        c1372jF.h = str != null ? new Regex("[\"<>^`{|}]").replace(str, "") : null;
        ArrayList arrayList = c1372jF.c;
        int size = arrayList.size();
        for (int i = 0; i < size; i++) {
            arrayList.set(i, o.b(0, 0, 227, (String) arrayList.get(i), "[]", true));
        }
        ArrayList arrayList2 = c1372jF.d;
        if (arrayList2 != null) {
            int size2 = arrayList2.size();
            for (int i2 = 0; i2 < size2; i2++) {
                String str2 = (String) arrayList2.get(i2);
                arrayList2.set(i2, str2 != null ? o.b(0, 0, 195, str2, "\\^`{|}", true) : null);
            }
        }
        String str3 = (String) c1372jF.i;
        c1372jF.i = str3 != null ? o.b(0, 0, 163, str3, " \"#<>\\^`{|}", true) : null;
        String string = c1372jF.toString();
        try {
            return new URI(string);
        } catch (URISyntaxException e) {
            try {
                URI uriCreate = URI.create(new Regex("[\\u0000-\\u001F\\u007F-\\u009F\\p{javaWhitespace}]").replace(string, ""));
                Intrinsics.checkNotNullExpressionValue(uriCreate, "{\n      // Unlikely edge…Unexpected!\n      }\n    }");
                return uriCreate;
            } catch (Exception unused) {
                throw new RuntimeException(e);
            }
        }
    }

    public final URL k() {
        try {
            return new URL(this.i);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public final String toString() {
        return this.i;
    }
}
