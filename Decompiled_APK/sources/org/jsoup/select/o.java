package org.jsoup.select;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3386r2;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jsoup.helper.ValidationException;

/* loaded from: classes3.dex */
public final class o {
    public static final String[] d = {",", SimpleComparison.GREATER_THAN_OPERATION, "+", "~", " "};
    public static final String[] e = {SimpleComparison.EQUAL_TO_OPERATION, "!=", "^=", "$=", "*=", "~="};
    public static final Pattern f = Pattern.compile("(([+-])?(\\d+)?)n(\\s*([+-])?\\s*\\d+)?", 2);
    public static final Pattern g = Pattern.compile("([+-])?(\\d+)");
    public final com.android.billingclient.api.d a;
    public final String b;
    public final ArrayList c = new ArrayList();

    public o(String str) {
        org.jsoup.helper.b.e(str);
        String strTrim = str.trim();
        this.b = strTrim;
        this.a = new com.android.billingclient.api.d(strTrim);
    }

    public static m j(String str) {
        try {
            return new o(str).i();
        } catch (IllegalArgumentException e2) {
            throw new Selector$SelectorParseException(e2.getMessage());
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x00aa  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0127  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x013d  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0149  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(char r11) {
        /*
            Method dump skipped, instructions count: 334
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: org.jsoup.select.o.a(char):void");
    }

    public final int b() {
        boolean z = true;
        String strTrim = this.a.c().trim();
        String[] strArr = org.jsoup.internal.a.a;
        if (strTrim == null || strTrim.length() == 0) {
            z = false;
            break;
        }
        int length = strTrim.length();
        for (int i = 0; i < length; i++) {
            if (!Character.isDigit(strTrim.codePointAt(i))) {
                z = false;
                break;
            }
        }
        if (z) {
            return Integer.parseInt(strTrim);
        }
        throw new ValidationException("Index must be numeric");
    }

    public final void c(boolean z) {
        String str = z ? ":containsOwn" : ":contains";
        com.android.billingclient.api.d dVar = this.a;
        dVar.e(str);
        String strN = com.android.billingclient.api.d.n(dVar.b('(', ')'));
        org.jsoup.helper.b.f(strN, str.concat("(text) query must not be empty"));
        this.c.add(z ? new e(strN, 4) : new e(strN, 5));
    }

    public final void d(boolean z) {
        String str = z ? ":containsWholeOwnText" : ":containsWholeText";
        com.android.billingclient.api.d dVar = this.a;
        dVar.e(str);
        String strN = com.android.billingclient.api.d.n(dVar.b('(', ')'));
        org.jsoup.helper.b.f(strN, str.concat("(text) query must not be empty"));
        this.c.add(z ? new e(strN, 6, false) : new e(strN, 7, false));
    }

    public final void e(boolean z, boolean z2) throws NumberFormatException {
        String strD = AbstractC3386r2.d(this.a.c());
        Matcher matcher = f.matcher(strD);
        Matcher matcher2 = g.matcher(strD);
        int i = 2;
        int i2 = 1;
        if (!"odd".equals(strD)) {
            if ("even".equals(strD)) {
                i2 = 0;
            } else if (matcher.matches()) {
                int i3 = matcher.group(3) != null ? Integer.parseInt(matcher.group(1).replaceFirst("^\\+", "")) : 1;
                i2 = matcher.group(4) != null ? Integer.parseInt(matcher.group(4).replaceFirst("^\\+", "")) : 0;
                i = i3;
            } else {
                if (!matcher2.matches()) {
                    throw new Selector$SelectorParseException("Could not parse nth-index '%s': unexpected format", strD);
                }
                i2 = Integer.parseInt(matcher2.group().replaceFirst("^\\+", ""));
                i = 0;
            }
        }
        ArrayList arrayList = this.c;
        if (z2) {
            if (z) {
                arrayList.add(new k(i, i2, 2));
                return;
            } else {
                arrayList.add(new k(i, i2, 3));
                return;
            }
        }
        if (z) {
            arrayList.add(new k(i, i2, 1));
        } else {
            arrayList.add(new k(i, i2, 0));
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final void f() throws NumberFormatException {
        int i = 9;
        int i2 = 4;
        int i3 = 3;
        int i4 = 1;
        int i5 = 2;
        boolean z = false;
        Object[] objArr = 0;
        Object[] objArr2 = 0;
        Object[] objArr3 = 0;
        Object[] objArr4 = 0;
        Object[] objArr5 = 0;
        Object[] objArr6 = 0;
        Object[] objArr7 = 0;
        com.android.billingclient.api.d dVar = this.a;
        boolean zI = dVar.i("#");
        ArrayList arrayList = this.c;
        if (zI) {
            String strF = dVar.f();
            org.jsoup.helper.b.e(strF);
            arrayList.add(new e(strF, 8, z));
            return;
        }
        if (dVar.i(".")) {
            String strF2 = dVar.f();
            org.jsoup.helper.b.e(strF2);
            arrayList.add(new e(strF2.trim(), i5, objArr7 == true ? 1 : 0));
            return;
        }
        if (dVar.l() || dVar.j("*|")) {
            int i6 = dVar.b;
            while (!dVar.h() && (dVar.l() || dVar.k("*|", "|", "_", "-"))) {
                dVar.b++;
            }
            String strD = AbstractC3386r2.d(dVar.c.substring(i6, dVar.b));
            org.jsoup.helper.b.e(strD);
            if (!strD.startsWith("*|")) {
                if (strD.contains("|")) {
                    strD = strD.replace("|", ":");
                }
                arrayList.add(new e(strD, i, objArr == true ? 1 : 0));
                return;
            }
            List listAsList = Arrays.asList(new e(strD.substring(2), i, objArr3 == true ? 1 : 0), new e(strD.replace("*|", ":"), 10, objArr2 == true ? 1 : 0));
            b bVar = new b();
            int i7 = bVar.b;
            ArrayList arrayList2 = bVar.a;
            if (i7 > 1) {
                arrayList2.add(new a(listAsList));
            } else {
                arrayList2.addAll(listAsList);
            }
            bVar.b = arrayList2.size();
            arrayList.add(bVar);
            return;
        }
        boolean zJ = dVar.j("[");
        String str = this.b;
        if (zJ) {
            com.android.billingclient.api.d dVar2 = new com.android.billingclient.api.d(dVar.b('[', ']'));
            String[] strArr = e;
            int i8 = dVar2.b;
            while (!dVar2.h() && !dVar2.k(strArr)) {
                dVar2.b++;
            }
            String strSubstring = dVar2.c.substring(i8, dVar2.b);
            org.jsoup.helper.b.e(strSubstring);
            dVar2.g();
            if (dVar2.h()) {
                if (strSubstring.startsWith("^")) {
                    arrayList.add(new e(strSubstring.substring(1), 1));
                    return;
                } else {
                    arrayList.add(new e(strSubstring, objArr6 == true ? 1 : 0, objArr5 == true ? 1 : 0));
                    return;
                }
            }
            if (dVar2.i(SimpleComparison.EQUAL_TO_OPERATION)) {
                arrayList.add(new f(strSubstring, 0, dVar2.m(), true));
                return;
            }
            if (dVar2.i("!=")) {
                arrayList.add(new f(strSubstring, 3, dVar2.m(), true));
                return;
            }
            if (dVar2.i("^=")) {
                arrayList.add(new f(strSubstring, 4, dVar2.m(), false));
                return;
            }
            if (dVar2.i("$=")) {
                arrayList.add(new f(strSubstring, 2, dVar2.m(), false));
                return;
            }
            if (dVar2.i("*=")) {
                arrayList.add(new f(strSubstring, 1, dVar2.m(), true));
                return;
            }
            if (!dVar2.i("~=")) {
                throw new Selector$SelectorParseException("Could not parse attribute query '%s': unexpected token at '%s'", str, dVar2.m());
            }
            Pattern patternCompile = Pattern.compile(dVar2.m());
            g gVar = new g();
            gVar.a = AbstractC3386r2.d(strSubstring);
            gVar.b = patternCompile;
            arrayList.add(gVar);
            return;
        }
        if (dVar.i("*")) {
            arrayList.add(new d(objArr4 == true ? 1 : 0));
            return;
        }
        if (dVar.i(":lt(")) {
            arrayList.add(new h(b(), 2));
            return;
        }
        if (dVar.i(":gt(")) {
            arrayList.add(new h(b(), 1));
            return;
        }
        if (dVar.i(":eq(")) {
            arrayList.add(new h(b(), 0));
            return;
        }
        if (dVar.j(":has(")) {
            dVar.e(":has");
            String strB = dVar.b('(', ')');
            org.jsoup.helper.b.f(strB, ":has(selector) sub-select must not be empty");
            arrayList.add(new p(j(strB)));
            return;
        }
        if (dVar.j(":contains(")) {
            c(false);
            return;
        }
        if (dVar.j(":containsOwn(")) {
            c(true);
            return;
        }
        if (dVar.j(":containsWholeText(")) {
            d(false);
            return;
        }
        if (dVar.j(":containsWholeOwnText(")) {
            d(true);
            return;
        }
        if (dVar.j(":containsData(")) {
            dVar.e(":containsData");
            String strN = com.android.billingclient.api.d.n(dVar.b('(', ')'));
            org.jsoup.helper.b.f(strN, ":containsData(text) query must not be empty");
            arrayList.add(new e(strN, 3));
            return;
        }
        if (dVar.j(":matches(")) {
            g(false);
            return;
        }
        if (dVar.j(":matchesOwn(")) {
            g(true);
            return;
        }
        if (dVar.j(":matchesWholeText(")) {
            h(false);
            return;
        }
        if (dVar.j(":matchesWholeOwnText(")) {
            h(true);
            return;
        }
        if (dVar.j(":not(")) {
            dVar.e(":not");
            String strB2 = dVar.b('(', ')');
            org.jsoup.helper.b.f(strB2, ":not(selector) subselect must not be empty");
            m mVarJ = j(strB2);
            q qVar = new q(i5);
            qVar.a = mVarJ;
            arrayList.add(qVar);
            return;
        }
        if (dVar.i(":nth-child(")) {
            e(false, false);
            return;
        }
        if (dVar.i(":nth-last-child(")) {
            e(true, false);
            return;
        }
        if (dVar.i(":nth-of-type(")) {
            e(false, true);
            return;
        }
        if (dVar.i(":nth-last-of-type(")) {
            e(true, true);
            return;
        }
        if (dVar.i(":first-child")) {
            arrayList.add(new d(i5));
            return;
        }
        if (dVar.i(":last-child")) {
            arrayList.add(new d(i3));
            return;
        }
        if (dVar.i(":first-of-type")) {
            arrayList.add(new i(0, 1, 3));
            return;
        }
        if (dVar.i(":last-of-type")) {
            arrayList.add(new j(0, 1, 2));
            return;
        }
        if (dVar.i(":only-child")) {
            arrayList.add(new d(i2));
            return;
        }
        if (dVar.i(":only-of-type")) {
            arrayList.add(new d(5));
            return;
        }
        if (dVar.i(":empty")) {
            arrayList.add(new d(i4));
        } else if (dVar.i(":root")) {
            arrayList.add(new d(6));
        } else {
            if (!dVar.i(":matchText")) {
                throw new Selector$SelectorParseException("Could not parse query '%s': unexpected token at '%s'", str, dVar.m());
            }
            arrayList.add(new d(7));
        }
    }

    public final void g(boolean z) {
        String str = z ? ":matchesOwn" : ":matches";
        com.android.billingclient.api.d dVar = this.a;
        dVar.e(str);
        String strB = dVar.b('(', ')');
        org.jsoup.helper.b.f(strB, str.concat("(regex) query must not be empty"));
        this.c.add(z ? new l(Pattern.compile(strB), 1) : new l(Pattern.compile(strB), 0));
    }

    public final void h(boolean z) {
        String str = z ? ":matchesWholeOwnText" : ":matchesWholeText";
        com.android.billingclient.api.d dVar = this.a;
        dVar.e(str);
        String strB = dVar.b('(', ')');
        org.jsoup.helper.b.f(strB, str.concat("(regex) query must not be empty"));
        this.c.add(z ? new l(Pattern.compile(strB), 2) : new l(Pattern.compile(strB), 3));
    }

    public final m i() throws NumberFormatException {
        com.android.billingclient.api.d dVar = this.a;
        dVar.g();
        String[] strArr = d;
        boolean zK = dVar.k(strArr);
        ArrayList arrayList = this.c;
        if (zK) {
            arrayList.add(new d(8));
            a(dVar.d());
        } else {
            f();
        }
        while (!dVar.h()) {
            boolean zG = dVar.g();
            if (dVar.k(strArr)) {
                a(dVar.d());
            } else if (zG) {
                a(' ');
            } else {
                f();
            }
        }
        return arrayList.size() == 1 ? (m) arrayList.get(0) : new a(arrayList);
    }

    public final String toString() {
        return this.b;
    }
}
