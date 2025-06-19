package org.jsoup.nodes;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3386r2;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.regex.Pattern;
import org.jsoup.SerializationException;

/* loaded from: classes3.dex */
public final class a implements Map.Entry, Cloneable {
    public static final String[] d = {"allowfullscreen", "async", "autofocus", "checked", "compact", "declare", "default", "defer", "disabled", "formnovalidate", "hidden", "inert", "ismap", "itemscope", "multiple", "muted", "nohref", "noresize", "noshade", "novalidate", "nowrap", "open", "readonly", "required", "reversed", "seamless", "selected", "sortable", "truespeed", "typemustmatch"};
    public static final Pattern e = Pattern.compile("[a-zA-Z_:][-a-zA-Z0-9_:.]*");
    public static final Pattern f = Pattern.compile("[^-a-zA-Z0-9_:.]");
    public static final Pattern g = Pattern.compile("[^\\x00-\\x1f\\x7f-\\x9f \"'/=]+");
    public static final Pattern h = Pattern.compile("[\\x00-\\x1f\\x7f-\\x9f \"'/=]");
    public final String a;
    public String b;
    public b c;

    public a(String str, String str2, b bVar) {
        org.jsoup.helper.b.g(str);
        String strTrim = str.trim();
        org.jsoup.helper.b.e(strTrim);
        this.a = strTrim;
        this.b = str2;
        this.c = bVar;
    }

    public static String b(int i, String str) {
        if (i == 2) {
            Pattern pattern = e;
            if (!pattern.matcher(str).matches()) {
                String strReplaceAll = f.matcher(str).replaceAll("");
                if (pattern.matcher(strReplaceAll).matches()) {
                    return strReplaceAll;
                }
                return null;
            }
        }
        if (i == 1) {
            Pattern pattern2 = g;
            if (!pattern2.matcher(str).matches()) {
                String strReplaceAll2 = h.matcher(str).replaceAll("");
                if (pattern2.matcher(strReplaceAll2).matches()) {
                    return strReplaceAll2;
                }
                return null;
            }
        }
        return str;
    }

    public static void c(String str, String str2, Appendable appendable, f fVar) throws IOException {
        appendable.append(str);
        if (fVar.h == 1) {
            if (str2 == null) {
                return;
            }
            if ((str2.isEmpty() || str2.equalsIgnoreCase(str)) && Arrays.binarySearch(d, AbstractC3386r2.c(str)) >= 0) {
                return;
            }
        }
        appendable.append("=\"");
        if (str2 == null) {
            str2 = "";
        }
        k.b(appendable, str2, fVar, true, false, false, false);
        appendable.append('\"');
    }

    public final Object clone() {
        try {
            return (a) super.clone();
        } catch (CloneNotSupportedException e2) {
            throw new RuntimeException(e2);
        }
    }

    @Override // java.util.Map.Entry
    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && a.class == obj.getClass()) {
            a aVar = (a) obj;
            String str = aVar.a;
            String str2 = this.a;
            if (str2 == null ? str != null : !str2.equals(str)) {
                return false;
            }
            String str3 = this.b;
            String str4 = aVar.b;
            if (str3 != null) {
                return str3.equals(str4);
            }
            if (str4 == null) {
                return true;
            }
        }
        return false;
    }

    @Override // java.util.Map.Entry
    public final Object getKey() {
        return this.a;
    }

    @Override // java.util.Map.Entry
    public final Object getValue() {
        String str = this.b;
        return str == null ? "" : str;
    }

    @Override // java.util.Map.Entry
    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str != null ? str.hashCode() : 0) * 31;
        String str2 = this.b;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    @Override // java.util.Map.Entry
    public final Object setValue(Object obj) {
        String str;
        int iN;
        String str2 = (String) obj;
        String strI = this.b;
        b bVar = this.c;
        if (bVar != null && (iN = bVar.n((str = this.a))) != -1) {
            strI = this.c.i(str);
            this.c.c[iN] = str2;
        }
        this.b = str2;
        return strI == null ? "" : strI;
    }

    public final String toString() {
        StringBuilder sbB = org.jsoup.internal.a.b();
        try {
            f fVar = new g("").j;
            String str = this.b;
            String strB = b(fVar.h, this.a);
            if (strB != null) {
                c(strB, str, sbB, fVar);
            }
            return org.jsoup.internal.a.g(sbB);
        } catch (IOException e2) {
            throw new SerializationException(e2);
        }
    }
}
