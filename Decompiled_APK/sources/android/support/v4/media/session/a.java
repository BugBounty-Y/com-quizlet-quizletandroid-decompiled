package android.support.v4.media.session;

import android.net.Uri;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.C0839z;
import androidx.compose.ui.node.C0912h;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public abstract /* synthetic */ class a {
    public static /* synthetic */ void A(Object obj) {
        if (obj != null) {
            throw new ClassCastException();
        }
    }

    public static String B(String str, String str2, String str3) {
        return str + str2 + str3;
    }

    public static float a(float f, float f2, float f3, float f4) {
        return ((f - f2) * f3) + f4;
    }

    public static int b(int i, float f, int i2) {
        return (Float.hashCode(f) + i) * i2;
    }

    public static C0839z c(C c, C0814p c0814p) {
        C0839z c0839z = new C0839z(c);
        c0814p.i0(c0839z);
        return c0839z;
    }

    public static ClassCastException d(Iterator it2) {
        it2.next().getClass();
        return new ClassCastException();
    }

    public static Object e(int i, ArrayList arrayList) {
        return arrayList.get(arrayList.size() - i);
    }

    public static String f(int i, String str) {
        return str + i;
    }

    public static String g(long j, String str, StringBuilder sb) {
        sb.append(j);
        sb.append(str);
        return sb.toString();
    }

    public static String h(Uri uri, String str) {
        return str + uri;
    }

    public static String i(String str, float f, String str2) {
        return str + f + str2;
    }

    public static String j(String str, int i, String str2, String str3, int i2) {
        return str + i + str2 + i2 + str3;
    }

    public static String k(String str, String str2) {
        return str + str2;
    }

    public static String l(String str, String str2, String str3) {
        return str + str2 + str3;
    }

    public static String m(String str, String str2, String str3, String str4) {
        return str + str2 + str3 + str4;
    }

    public static String n(String str, StringBuilder sb, List list) {
        sb.append(list);
        sb.append(str);
        return sb.toString();
    }

    public static String o(String str, StringBuilder sb, boolean z) {
        sb.append(z);
        sb.append(str);
        return sb.toString();
    }

    public static String p(StringBuilder sb, float f, char c) {
        sb.append(f);
        sb.append(c);
        return sb.toString();
    }

    public static String q(StringBuilder sb, int i, char c) {
        sb.append(i);
        sb.append(c);
        return sb.toString();
    }

    public static String r(StringBuilder sb, int i, String str) {
        sb.append(i);
        sb.append(str);
        return sb.toString();
    }

    public static String s(StringBuilder sb, Object obj, String str) {
        sb.append(obj);
        sb.append(str);
        return sb.toString();
    }

    public static String t(StringBuilder sb, String str, String str2) {
        sb.append(str);
        sb.append(str2);
        return sb.toString();
    }

    public static String u(StringBuilder sb, boolean z, char c) {
        sb.append(z);
        sb.append(c);
        return sb.toString();
    }

    public static StringBuilder v(int i, String str, String str2) {
        StringBuilder sb = new StringBuilder(str);
        sb.append(i);
        sb.append(str2);
        return sb;
    }

    public static StringBuilder w(String str, int i, String str2, String str3, int i2) {
        StringBuilder sb = new StringBuilder(str);
        sb.append(i);
        sb.append(str2);
        sb.append(i2);
        sb.append(str3);
        return sb;
    }

    public static StringBuilder x(String str, String str2) {
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        sb.append(str2);
        return sb;
    }

    public static StringBuilder y(String str, String str2, String str3) {
        StringBuilder sb = new StringBuilder(str);
        sb.append(str2);
        sb.append(str3);
        return sb;
    }

    public static void z(int i, C0814p c0814p, int i2, C0912h c0912h) {
        c0814p.i0(Integer.valueOf(i));
        c0814p.b(Integer.valueOf(i2), c0912h);
    }
}
