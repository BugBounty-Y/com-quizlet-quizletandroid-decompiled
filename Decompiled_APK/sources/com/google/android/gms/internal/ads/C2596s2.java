package com.google.android.gms.internal.ads;

import android.text.SpannableStringBuilder;
import android.util.Pair;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

/* renamed from: com.google.android.gms.internal.ads.s2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2596s2 {
    public final String a;
    public final String b;
    public final boolean c;
    public final long d;
    public final long e;
    public final C2725v2 f;
    public final String[] g;
    public final String h;
    public final String i;
    public final C2596s2 j;
    public final HashMap k;
    public final HashMap l;
    public ArrayList m;

    public C2596s2(String str, String str2, long j, long j2, C2725v2 c2725v2, String[] strArr, String str3, String str4, C2596s2 c2596s2) {
        this.a = str;
        this.b = str2;
        this.i = str4;
        this.f = c2725v2;
        this.g = strArr;
        this.c = str2 != null;
        this.d = j;
        this.e = j2;
        str3.getClass();
        this.h = str3;
        this.j = c2596s2;
        this.k = new HashMap();
        this.l = new HashMap();
    }

    public static C2596s2 b(String str, long j, long j2, C2725v2 c2725v2, String[] strArr, String str2, String str3, C2596s2 c2596s2) {
        return new C2596s2(str, null, j, j2, c2725v2, strArr, str2, str3, c2596s2);
    }

    public static C2596s2 c(String str) {
        return new C2596s2(null, str.replaceAll("\r\n", "\n").replaceAll(" *\n *", "\n").replaceAll("\n", " ").replaceAll("[ \t\\x0B\f\r]+", " "), -9223372036854775807L, -9223372036854775807L, null, null, "", null, null);
    }

    public static SpannableStringBuilder f(String str, TreeMap treeMap) {
        if (!treeMap.containsKey(str)) {
            C2788wg c2788wg = new C2788wg();
            c2788wg.a = new SpannableStringBuilder();
            treeMap.put(str, c2788wg);
        }
        CharSequence charSequence = ((C2788wg) treeMap.get(str)).a;
        charSequence.getClass();
        return (SpannableStringBuilder) charSequence;
    }

    public final int a() {
        ArrayList arrayList = this.m;
        if (arrayList == null) {
            return 0;
        }
        return arrayList.size();
    }

    public final C2596s2 d(int i) {
        ArrayList arrayList = this.m;
        if (arrayList != null) {
            return (C2596s2) arrayList.get(i);
        }
        throw new IndexOutOfBoundsException();
    }

    public final boolean e(long j) {
        long j2 = this.d;
        long j3 = this.e;
        if (j2 == -9223372036854775807L) {
            if (j3 == -9223372036854775807L) {
                return true;
            }
            j2 = -9223372036854775807L;
        }
        if (j2 <= j && j3 == -9223372036854775807L) {
            return true;
        }
        if (j2 != -9223372036854775807L || j >= j3) {
            return j2 <= j && j < j3;
        }
        return true;
    }

    public final void g(TreeSet treeSet, boolean z) {
        String str = this.a;
        boolean zEquals = "p".equals(str);
        boolean zEquals2 = "div".equals(str);
        if (z || zEquals || (zEquals2 && this.i != null)) {
            long j = this.d;
            if (j != -9223372036854775807L) {
                treeSet.add(Long.valueOf(j));
            }
            long j2 = this.e;
            if (j2 != -9223372036854775807L) {
                treeSet.add(Long.valueOf(j2));
            }
        }
        if (this.m != null) {
            for (int i = 0; i < this.m.size(); i++) {
                C2596s2 c2596s2 = (C2596s2) this.m.get(i);
                boolean z2 = true;
                if (!z && !zEquals) {
                    z2 = false;
                }
                c2596s2.g(treeSet, z2);
            }
        }
    }

    public final void h(long j, String str, ArrayList arrayList) {
        String str2;
        String str3 = this.h;
        if (true != "".equals(str3)) {
            str = str3;
        }
        if (e(j) && "div".equals(this.a) && (str2 = this.i) != null) {
            arrayList.add(new Pair(str, str2));
            return;
        }
        for (int i = 0; i < a(); i++) {
            d(i).h(j, str, arrayList);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:141:0x020f  */
    /* JADX WARN: Removed duplicated region for block: B:144:0x021d  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x0291  */
    /* JADX WARN: Removed duplicated region for block: B:171:0x02ab  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00b3  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00b9  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x00bb  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i(long r21, java.util.Map r23, java.util.HashMap r24, java.lang.String r25, java.util.TreeMap r26) {
        /*
            Method dump skipped, instructions count: 758
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2596s2.i(long, java.util.Map, java.util.HashMap, java.lang.String, java.util.TreeMap):void");
    }

    public final void j(long j, boolean z, String str, TreeMap treeMap) {
        long j2;
        boolean z2;
        HashMap map = this.k;
        map.clear();
        HashMap map2 = this.l;
        map2.clear();
        String str2 = this.a;
        if ("metadata".equals(str2)) {
            return;
        }
        String str3 = this.h;
        String str4 = true != "".equals(str3) ? str3 : str;
        if (this.c && z) {
            SpannableStringBuilder spannableStringBuilderF = f(str4, treeMap);
            String str5 = this.b;
            str5.getClass();
            spannableStringBuilderF.append((CharSequence) str5);
            return;
        }
        if ("br".equals(str2) && z) {
            f(str4, treeMap).append('\n');
            return;
        }
        if (e(j)) {
            for (Map.Entry entry : treeMap.entrySet()) {
                String str6 = (String) entry.getKey();
                CharSequence charSequence = ((C2788wg) entry.getValue()).a;
                charSequence.getClass();
                map.put(str6, Integer.valueOf(charSequence.length()));
            }
            boolean zEquals = "p".equals(str2);
            for (int i = 0; i < a(); i++) {
                C2596s2 c2596s2D = d(i);
                if (z || zEquals) {
                    j2 = j;
                    z2 = true;
                } else {
                    j2 = j;
                    z2 = false;
                }
                c2596s2D.j(j2, z2, str4, treeMap);
            }
            if (zEquals) {
                SpannableStringBuilder spannableStringBuilderF2 = f(str4, treeMap);
                int length = spannableStringBuilderF2.length();
                do {
                    length--;
                    if (length < 0) {
                        break;
                    }
                } while (spannableStringBuilderF2.charAt(length) == ' ');
                if (length >= 0 && spannableStringBuilderF2.charAt(length) != '\n') {
                    spannableStringBuilderF2.append('\n');
                }
            }
            for (Map.Entry entry2 : treeMap.entrySet()) {
                String str7 = (String) entry2.getKey();
                CharSequence charSequence2 = ((C2788wg) entry2.getValue()).a;
                charSequence2.getClass();
                map2.put(str7, Integer.valueOf(charSequence2.length()));
            }
        }
    }
}
