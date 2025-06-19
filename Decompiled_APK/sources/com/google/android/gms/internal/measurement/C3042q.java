package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3554w3;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* renamed from: com.google.android.gms.internal.measurement.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3042q implements Iterable, InterfaceC3027n {
    public final String a;

    public C3042q(String str) {
        if (str == null) {
            throw new IllegalArgumentException("StringValue cannot be null.");
        }
        this.a = str;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n c(String str, C1721Kc c1721Kc, ArrayList arrayList) {
        String str2;
        String str3;
        String str4;
        String str5;
        char c;
        int i;
        String strZzi;
        int i2;
        int i3;
        int i4;
        C1721Kc c1721Kc2;
        int iA;
        if ("charAt".equals(str) || "concat".equals(str) || "hasOwnProperty".equals(str) || "indexOf".equals(str) || "lastIndexOf".equals(str) || "match".equals(str) || "replace".equals(str) || "search".equals(str) || "slice".equals(str) || "split".equals(str) || "substring".equals(str) || "toLowerCase".equals(str) || "toLocaleLowerCase".equals(str) || "toString".equals(str) || "toUpperCase".equals(str) || "toLocaleUpperCase".equals(str)) {
            str2 = "hasOwnProperty";
            str3 = "trim";
        } else {
            str2 = "hasOwnProperty";
            str3 = "trim";
            if (!str3.equals(str)) {
                throw new IllegalArgumentException(str.concat(" is not a String function"));
            }
        }
        switch (str.hashCode()) {
            case -1789698943:
                str4 = str2;
                str5 = "charAt";
                if (str.equals(str4)) {
                    c = 2;
                    break;
                } else {
                    c = 65535;
                    break;
                }
            case -1776922004:
                str5 = "charAt";
                if (str.equals("toString")) {
                    c = 14;
                    str4 = str2;
                    break;
                }
                str4 = str2;
                c = 65535;
                break;
            case -1464939364:
                str5 = "charAt";
                if (str.equals("toLocaleLowerCase")) {
                    c = '\f';
                    str4 = str2;
                    break;
                }
                str4 = str2;
                c = 65535;
                break;
            case -1361633751:
                str5 = "charAt";
                if (str.equals(str5)) {
                    str4 = str2;
                    c = 0;
                    break;
                }
                str4 = str2;
                c = 65535;
                break;
            case -1354795244:
                if (str.equals("concat")) {
                    str4 = str2;
                    str5 = "charAt";
                    c = 1;
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case -1137582698:
                if (str.equals("toLowerCase")) {
                    c = '\r';
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case -906336856:
                if (str.equals("search")) {
                    c = 7;
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case -726908483:
                if (str.equals("toLocaleUpperCase")) {
                    c = 11;
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case -467511597:
                if (str.equals("lastIndexOf")) {
                    c = 4;
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case -399551817:
                if (str.equals("toUpperCase")) {
                    c = 15;
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case 3568674:
                if (str.equals(str3)) {
                    c = 16;
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case 103668165:
                if (str.equals("match")) {
                    c = 5;
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case 109526418:
                if (str.equals("slice")) {
                    c = '\b';
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case 109648666:
                if (str.equals("split")) {
                    c = '\t';
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case 530542161:
                if (str.equals("substring")) {
                    c = '\n';
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case 1094496948:
                if (str.equals("replace")) {
                    c = 6;
                    str4 = str2;
                    str5 = "charAt";
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            case 1943291465:
                if (str.equals("indexOf")) {
                    str4 = str2;
                    str5 = "charAt";
                    c = 3;
                    break;
                }
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
            default:
                str4 = str2;
                str5 = "charAt";
                c = 65535;
                break;
        }
        char c2 = c;
        String str6 = this.a;
        switch (c2) {
            case 0:
                AbstractC3554w3.i(1, str5, arrayList);
                int iA2 = !arrayList.isEmpty() ? (int) AbstractC3554w3.a(((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0)).g().doubleValue()) : 0;
                return (iA2 < 0 || iA2 >= str6.length()) ? InterfaceC3027n.X0 : new C3042q(String.valueOf(str6.charAt(iA2)));
            case 1:
                if (!arrayList.isEmpty()) {
                    StringBuilder sb = new StringBuilder(str6);
                    for (int i5 = 0; i5 < arrayList.size(); i5++) {
                        sb.append(((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(i5)).zzi());
                    }
                    return new C3042q(sb.toString());
                }
                return this;
            case 2:
                AbstractC3554w3.g(str4, arrayList, 1);
                InterfaceC3027n interfaceC3027nA = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0));
                boolean zEquals = "length".equals(interfaceC3027nA.zzi());
                C2982e c2982e = InterfaceC3027n.V0;
                if (zEquals) {
                    return c2982e;
                }
                double dDoubleValue = interfaceC3027nA.g().doubleValue();
                return (dDoubleValue != Math.floor(dDoubleValue) || (i = (int) dDoubleValue) < 0 || i >= str6.length()) ? InterfaceC3027n.W0 : c2982e;
            case 3:
                AbstractC3554w3.i(2, "indexOf", arrayList);
                return new C2992g(Double.valueOf(str6.indexOf(arrayList.size() > 0 ? ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0)).zzi() : "undefined", (int) AbstractC3554w3.a(arrayList.size() < 2 ? 0.0d : ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(1)).g().doubleValue()))));
            case 4:
                AbstractC3554w3.i(2, "lastIndexOf", arrayList);
                String strZzi2 = arrayList.size() > 0 ? ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0)).zzi() : "undefined";
                return new C2992g(Double.valueOf(str6.lastIndexOf(strZzi2, (int) (Double.isNaN(arrayList.size() < 2 ? Double.NaN : ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(1)).g().doubleValue()) ? Double.POSITIVE_INFINITY : AbstractC3554w3.a(r3)))));
            case 5:
                AbstractC3554w3.i(1, "match", arrayList);
                Matcher matcher = Pattern.compile(arrayList.size() <= 0 ? "" : ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0)).zzi()).matcher(str6);
                return matcher.find() ? new C2977d(Arrays.asList(new C3042q(matcher.group()))) : InterfaceC3027n.R0;
            case 6:
                AbstractC3554w3.i(2, "replace", arrayList);
                InterfaceC3027n interfaceC3027nD = InterfaceC3027n.Q0;
                if (!arrayList.isEmpty()) {
                    strZzi = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0)).zzi();
                    if (arrayList.size() > 1) {
                        interfaceC3027nD = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(1));
                    }
                }
                String str7 = strZzi;
                int iIndexOf = str6.indexOf(str7);
                if (iIndexOf >= 0) {
                    if (interfaceC3027nD instanceof AbstractC2997h) {
                        i2 = 0;
                        interfaceC3027nD = ((AbstractC2997h) interfaceC3027nD).d(c1721Kc, Arrays.asList(new C3042q(str7), new C2992g(Double.valueOf(iIndexOf)), this));
                    } else {
                        i2 = 0;
                    }
                    return new C3042q(android.support.v4.media.session.a.l(str6.substring(i2, iIndexOf), interfaceC3027nD.zzi(), str6.substring(str7.length() + iIndexOf)));
                }
                return this;
            case 7:
                AbstractC3554w3.i(1, "search", arrayList);
                return Pattern.compile(arrayList.isEmpty() ? "undefined" : ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0)).zzi()).matcher(str6).find() ? new C2992g(Double.valueOf(r1.start())) : new C2992g(Double.valueOf(-1.0d));
            case '\b':
                AbstractC3554w3.i(2, "slice", arrayList);
                double dA = AbstractC3554w3.a(!arrayList.isEmpty() ? ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0)).g().doubleValue() : 0.0d);
                double dMax = dA < 0.0d ? Math.max(str6.length() + dA, 0.0d) : Math.min(dA, str6.length());
                double dA2 = AbstractC3554w3.a(arrayList.size() > 1 ? ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(1)).g().doubleValue() : str6.length());
                int i6 = (int) dMax;
                return new C3042q(str6.substring(i6, Math.max(0, ((int) (dA2 < 0.0d ? Math.max(str6.length() + dA2, 0.0d) : Math.min(dA2, str6.length()))) - i6) + i6));
            case '\t':
                AbstractC3554w3.i(2, "split", arrayList);
                if (str6.length() == 0) {
                    return new C2977d(Arrays.asList(this));
                }
                ArrayList arrayList2 = new ArrayList();
                if (arrayList.isEmpty()) {
                    arrayList2.add(this);
                } else {
                    String strZzi3 = ((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(0)).zzi();
                    long jB = arrayList.size() > 1 ? AbstractC3554w3.b(((C3056t) c1721Kc.c).a(c1721Kc, (InterfaceC3027n) arrayList.get(1)).g().doubleValue()) & 4294967295L : 2147483647L;
                    if (jB == 0) {
                        return new C2977d();
                    }
                    String[] strArrSplit = str6.split(Pattern.quote(strZzi3), ((int) jB) + 1);
                    int length = strArrSplit.length;
                    if (!strZzi3.isEmpty() || length <= 0) {
                        i3 = length;
                        i4 = 0;
                    } else {
                        boolean zIsEmpty = strArrSplit[0].isEmpty();
                        i3 = length - 1;
                        i4 = zIsEmpty;
                        if (!strArrSplit[i3].isEmpty()) {
                            i3 = length;
                            i4 = zIsEmpty;
                        }
                    }
                    if (length > jB) {
                        i3--;
                    }
                    while (i4 < i3) {
                        arrayList2.add(new C3042q(strArrSplit[i4]));
                        i4++;
                    }
                }
                return new C2977d(arrayList2);
            case '\n':
                AbstractC3554w3.i(2, "substring", arrayList);
                if (arrayList.isEmpty()) {
                    c1721Kc2 = c1721Kc;
                    iA = 0;
                } else {
                    c1721Kc2 = c1721Kc;
                    iA = (int) AbstractC3554w3.a(((C3056t) c1721Kc2.c).a(c1721Kc2, (InterfaceC3027n) arrayList.get(0)).g().doubleValue());
                }
                int iA3 = arrayList.size() > 1 ? (int) AbstractC3554w3.a(((C3056t) c1721Kc2.c).a(c1721Kc2, (InterfaceC3027n) arrayList.get(1)).g().doubleValue()) : str6.length();
                int iMin = Math.min(Math.max(iA, 0), str6.length());
                int iMin2 = Math.min(Math.max(iA3, 0), str6.length());
                return new C3042q(str6.substring(Math.min(iMin, iMin2), Math.max(iMin, iMin2)));
            case 11:
                AbstractC3554w3.g("toLocaleUpperCase", arrayList, 0);
                return new C3042q(str6.toUpperCase());
            case '\f':
                AbstractC3554w3.g("toLocaleLowerCase", arrayList, 0);
                return new C3042q(str6.toLowerCase());
            case '\r':
                AbstractC3554w3.g("toLowerCase", arrayList, 0);
                return new C3042q(str6.toLowerCase(Locale.ENGLISH));
            case 14:
                AbstractC3554w3.g("toString", arrayList, 0);
                return this;
            case 15:
                AbstractC3554w3.g("toUpperCase", arrayList, 0);
                return new C3042q(str6.toUpperCase(Locale.ENGLISH));
            case 16:
                AbstractC3554w3.g("toUpperCase", arrayList, 0);
                return new C3042q(str6.trim());
            default:
                throw new IllegalArgumentException("Command not supported");
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof C3042q) {
            return this.a.equals(((C3042q) obj).a);
        }
        return false;
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Double g() {
        String str = this.a;
        if (str.isEmpty()) {
            return Double.valueOf(0.0d);
        }
        try {
            return Double.valueOf(str);
        } catch (NumberFormatException unused) {
            return Double.valueOf(Double.NaN);
        }
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Boolean h() {
        return Boolean.valueOf(!this.a.isEmpty());
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return new C3037p(this, 1);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final InterfaceC3027n j() {
        return new C3042q(this.a);
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final Iterator k() {
        return new C3037p(this, 0);
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("\""), this.a, "\"");
    }

    @Override // com.google.android.gms.internal.measurement.InterfaceC3027n
    public final String zzi() {
        return this.a;
    }
}
