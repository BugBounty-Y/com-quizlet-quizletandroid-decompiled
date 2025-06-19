package com.google.android.gms.internal.mlkit_vision_camera;

import android.os.Build;
import android.os.Bundle;
import androidx.activity.AbstractC0037i;
import androidx.transition.C1405h;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.ArrayList;
import kotlin.jvm.internal.C4950i;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlin.text.StringsKt;
import okhttp3.C5083l;
import okhttp3.internal.publicsuffix.PublicSuffixDatabase;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.e2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3335e2 {
    public static final /* synthetic */ int a = 0;

    public static final boolean a(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return bundle.containsKey(key);
    }

    public static int b(int i, int i2, String str, boolean z) {
        while (i < i2) {
            char cCharAt = str.charAt(i);
            if (((cCharAt < ' ' && cCharAt != '\t') || cCharAt >= 127 || ('0' <= cCharAt && cCharAt < ':') || (('a' <= cCharAt && cCharAt < '{') || (('A' <= cCharAt && cCharAt < '[') || cCharAt == ':'))) == (!z)) {
                return i;
            }
            i++;
        }
        return i2;
    }

    public static boolean c(String str, String str2) {
        if (!Intrinsics.b(str, str2)) {
            if (kotlin.text.D.k(str, str2, false) && str.charAt((str.length() - str2.length()) - 1) == '.') {
                byte[] bArr = okhttp3.internal.b.a;
                Intrinsics.checkNotNullParameter(str, "<this>");
                if (!okhttp3.internal.b.f.e(str)) {
                }
            }
            return false;
        }
        return true;
    }

    public static final double d(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        double d = bundle.getDouble(key, Double.MIN_VALUE);
        if (d != Double.MIN_VALUE || bundle.getDouble(key, Double.MAX_VALUE) != Double.MAX_VALUE) {
            return d;
        }
        AbstractC3339f2.h(key);
        throw null;
    }

    public static final float e(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        float f = bundle.getFloat(key, Float.MIN_VALUE);
        if (f != Float.MIN_VALUE || bundle.getFloat(key, Float.MAX_VALUE) != Float.MAX_VALUE) {
            return f;
        }
        AbstractC3339f2.h(key);
        throw null;
    }

    public static final int f(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        int i = bundle.getInt(key, Integer.MIN_VALUE);
        if (i != Integer.MIN_VALUE || bundle.getInt(key, SubsamplingScaleImageView.TILE_SIZE_AUTO) != Integer.MAX_VALUE) {
            return i;
        }
        AbstractC3339f2.h(key);
        throw null;
    }

    public static final long g(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        long j = bundle.getLong(key, Long.MIN_VALUE);
        if (j != Long.MIN_VALUE || bundle.getLong(key, Long.MAX_VALUE) != Long.MAX_VALUE) {
            return j;
        }
        AbstractC3339f2.h(key);
        throw null;
    }

    public static final Bundle h(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        Bundle bundle2 = bundle.getBundle(key);
        if (bundle2 != null) {
            return bundle2;
        }
        AbstractC3339f2.h(key);
        throw null;
    }

    public static final ArrayList i(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        C4950i parcelableClass = kotlin.jvm.internal.K.a(Bundle.class);
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(parcelableClass, "parcelableClass");
        ArrayList arrayListC = Build.VERSION.SDK_INT >= 34 ? AbstractC0037i.c(bundle, key, kotlin.jvm.a.b(parcelableClass)) : bundle.getParcelableArrayList(key);
        if (arrayListC != null) {
            return arrayListC;
        }
        AbstractC3339f2.h(key);
        throw null;
    }

    public static final String[] j(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        String[] stringArray = bundle.getStringArray(key);
        if (stringArray != null) {
            return stringArray;
        }
        AbstractC3339f2.h(key);
        throw null;
    }

    public static final boolean k(Bundle bundle, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        return a(bundle, key) && bundle.get(key) == null;
    }

    public static C5083l l(okhttp3.s url, String setCookie) {
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(setCookie, "setCookie");
        long jCurrentTimeMillis = System.currentTimeMillis();
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(setCookie, "setCookie");
        char c = ';';
        int iH = okhttp3.internal.b.h(setCookie, ';', 0, 0, 6);
        char c2 = '=';
        int iH2 = okhttp3.internal.b.h(setCookie, '=', 0, iH, 2);
        String str = null;
        if (iH2 != iH) {
            String strA = okhttp3.internal.b.A(0, iH2, setCookie);
            if (strA.length() != 0 && okhttp3.internal.b.n(strA) == -1) {
                boolean z = true;
                String strA2 = okhttp3.internal.b.A(iH2 + 1, iH, setCookie);
                if (okhttp3.internal.b.n(strA2) == -1) {
                    int i = iH + 1;
                    int length = setCookie.length();
                    long j = 253402300799999L;
                    boolean z2 = false;
                    boolean z3 = false;
                    boolean z4 = false;
                    String str2 = null;
                    boolean z5 = true;
                    long jM = 253402300799999L;
                    long j2 = -1;
                    while (true) {
                        if (i >= length) {
                            if (j2 == Long.MIN_VALUE) {
                                j = Long.MIN_VALUE;
                            } else if (j2 != -1) {
                                long j3 = jCurrentTimeMillis + (j2 <= 9223372036854775L ? j2 * 1000 : Long.MAX_VALUE);
                                if (j3 >= jCurrentTimeMillis && j3 <= 253402300799999L) {
                                    j = j3;
                                }
                            } else {
                                j = jM;
                            }
                            String str3 = url.d;
                            if (str != null) {
                                if (c(str3, str)) {
                                }
                                return null;
                            }
                            str = str3;
                            if (str3.length() == str.length() || PublicSuffixDatabase.g.a(str) != null) {
                                String strSubstring = "/";
                                if (str2 == null || !kotlin.text.D.r(str2, "/", false)) {
                                    String strB = url.b();
                                    int iP = StringsKt.P(strB, '/', 0, 6);
                                    if (iP != 0) {
                                        strSubstring = strB.substring(0, iP);
                                        Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
                                    }
                                    str2 = strSubstring;
                                }
                                return new C5083l(strA, strA2, j, str, str2, z4, z2, z3, z5);
                            }
                            return null;
                        }
                        int iF = okhttp3.internal.b.f(setCookie, c, i, length);
                        int iF2 = okhttp3.internal.b.f(setCookie, c2, i, iF);
                        String strA3 = okhttp3.internal.b.A(i, iF2, setCookie);
                        String strA4 = iF2 < iF ? okhttp3.internal.b.A(iF2 + 1, iF, setCookie) : "";
                        if (kotlin.text.D.l(strA3, "expires", z)) {
                            try {
                                jM = m(strA4.length(), strA4);
                                z3 = z;
                            } catch (IllegalArgumentException unused) {
                            }
                        } else if (kotlin.text.D.l(strA3, "max-age", z)) {
                            try {
                                j2 = Long.parseLong(strA4);
                                if (j2 <= 0) {
                                    j2 = Long.MIN_VALUE;
                                }
                            } catch (NumberFormatException e) {
                                try {
                                    if (!new Regex("-?\\d+").e(strA4)) {
                                        throw e;
                                    }
                                    j2 = kotlin.text.D.r(strA4, "-", false) ? Long.MIN_VALUE : Long.MAX_VALUE;
                                } catch (NumberFormatException | IllegalArgumentException unused2) {
                                }
                            }
                            z = true;
                            z3 = true;
                        } else if (!kotlin.text.D.l(strA3, "domain", true)) {
                            z = true;
                            if (kotlin.text.D.l(strA3, "path", true)) {
                                str2 = strA4;
                            } else if (kotlin.text.D.l(strA3, "secure", true)) {
                                z4 = true;
                            } else if (kotlin.text.D.l(strA3, "httponly", true)) {
                                z2 = true;
                            }
                        } else {
                            if (kotlin.text.D.k(strA4, ".", false)) {
                                throw new IllegalArgumentException("Failed requirement.");
                            }
                            String strD = C1405h.d(StringsKt.T(strA4, "."));
                            if (strD == null) {
                                throw new IllegalArgumentException();
                            }
                            str = strD;
                            z5 = false;
                            z = true;
                        }
                        i = iF + 1;
                        c = ';';
                        c2 = '=';
                    }
                }
            }
        }
        return null;
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x00a0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static long m(int r14, java.lang.String r15) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 321
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2.m(int, java.lang.String):long");
    }
}
