package androidx.compose.animation;

import androidx.compose.runtime.C0811n0;
import androidx.compose.runtime.C0814p;
import androidx.compose.ui.graphics.C0861v;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract /* synthetic */ class d0 {
    public static int a(double d, int i, int i2) {
        return (Double.hashCode(d) + i) * i2;
    }

    public static int b(int i, int i2, int i3) {
        return (Integer.hashCode(i) + i2) * i3;
    }

    public static int c(int i, int i2, int i3, int i4) {
        return ((i - i2) * i3) + i4;
    }

    public static int d(int i, int i2, long j) {
        return (Long.hashCode(j) + i) * i2;
    }

    public static int e(int i, int i2, String str) {
        return (str.hashCode() + i) * i2;
    }

    public static int f(int i, int i2, List list) {
        return (list.hashCode() + i) * i2;
    }

    public static int g(int i, int i2, boolean z) {
        return (Boolean.hashCode(z) + i) * i2;
    }

    public static int h(ArrayList arrayList, int i, int i2) {
        return (arrayList.hashCode() + i) * i2;
    }

    public static androidx.compose.foundation.interaction.m i(C0814p c0814p) {
        androidx.compose.foundation.interaction.m mVar = new androidx.compose.foundation.interaction.m();
        c0814p.i0(mVar);
        return mVar;
    }

    public static C0811n0 j(long j, androidx.compose.runtime.B b) {
        return b.a(new C0861v(j));
    }

    public static C0861v k(C0814p c0814p, boolean z, long j) {
        c0814p.p(z);
        return new C0861v(j);
    }

    public static ClassCastException l(Object obj) {
        obj.getClass();
        return new ClassCastException();
    }

    public static String m(char c, int i, String str) {
        return str + i + c;
    }

    public static String n(long j, String str) {
        return str + j;
    }

    public static String o(long j, String str, String str2) {
        return str + j + str2;
    }

    public static String p(String str, int i, String str2, int i2) {
        return str + i + str2 + i2;
    }

    public static String q(StringBuilder sb, long j, char c) {
        sb.append(j);
        sb.append(c);
        return sb.toString();
    }

    public static String r(StringBuilder sb, String str, char c) {
        sb.append(str);
        sb.append(c);
        return sb.toString();
    }

    public static String s(Object[] objArr, int i, String str, String str2) {
        String str3 = String.format(str, Arrays.copyOf(objArr, i));
        Intrinsics.checkNotNullExpressionValue(str3, str2);
        return str3;
    }

    public static StringBuilder t(long j, String str, String str2) {
        StringBuilder sb = new StringBuilder(str);
        sb.append(j);
        sb.append(str2);
        return sb;
    }

    public static StringBuilder u(String str) {
        StringBuilder sb = new StringBuilder();
        sb.append(str);
        return sb;
    }

    public static void v(int i, int i2, int i3, int i4, int i5) {
        androidx.compose.ui.input.key.c.a(i);
        androidx.compose.ui.input.key.c.a(i2);
        androidx.compose.ui.input.key.c.a(i3);
        androidx.compose.ui.input.key.c.a(i4);
        androidx.compose.ui.input.key.c.a(i5);
    }

    public static void w(int i, androidx.compose.runtime.internal.d dVar, C0814p c0814p, boolean z) {
        dVar.invoke(c0814p, Integer.valueOf(i));
        c0814p.p(z);
    }

    public static void x(long j, String str, StringBuilder sb) {
        sb.append((Object) C0861v.i(j));
        sb.append(str);
    }

    public static void y(com.quizlet.data.repository.folderset.c cVar, long j) {
        cVar.o().q();
        cVar.y(j);
    }

    public static /* synthetic */ String z(int i) {
        return i != 1 ? i != 2 ? i != 3 ? "null" : "COLLAPSED" : "NOT_CROSSED" : "CROSSED";
    }
}
