package com.google.android.gms.internal.mlkit_vision_camera;

import java.util.Collection;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.text.StringsKt;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.u1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3397u1 {
    public static final /* synthetic */ int a = 0;

    public static final long a(String str) throws NumberFormatException {
        kotlin.time.d unit;
        char cCharAt;
        int length = str.length();
        if (length == 0) {
            throw new IllegalArgumentException("The string is empty");
        }
        kotlin.time.b.b.getClass();
        char cCharAt2 = str.charAt(0);
        int i = (cCharAt2 == '+' || cCharAt2 == '-') ? 1 : 0;
        boolean z = (i > 0) && StringsKt.X(str, '-');
        if (length <= i) {
            throw new IllegalArgumentException("No components");
        }
        if (str.charAt(i) != 'P') {
            throw new IllegalArgumentException();
        }
        int i2 = i + 1;
        if (i2 == length) {
            throw new IllegalArgumentException();
        }
        kotlin.time.d dVar = null;
        long jH = 0;
        boolean z2 = false;
        while (i2 < length) {
            if (str.charAt(i2) != 'T') {
                int i3 = i2;
                while (i3 < str.length() && (('0' <= (cCharAt = str.charAt(i3)) && cCharAt < ':') || StringsKt.F("+-.", cCharAt, false))) {
                    i3++;
                }
                String strSubstring = str.substring(i2, i3);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
                if (strSubstring.length() == 0) {
                    throw new IllegalArgumentException();
                }
                int length2 = strSubstring.length() + i2;
                if (length2 < 0 || length2 >= str.length()) {
                    throw new IllegalArgumentException("Missing unit for value ".concat(strSubstring));
                }
                char cCharAt3 = str.charAt(length2);
                int i4 = length2 + 1;
                if (z2) {
                    if (cCharAt3 == 'H') {
                        unit = kotlin.time.d.f;
                    } else if (cCharAt3 == 'M') {
                        unit = kotlin.time.d.e;
                    } else {
                        if (cCharAt3 != 'S') {
                            throw new IllegalArgumentException("Invalid duration ISO time unit: " + cCharAt3);
                        }
                        unit = kotlin.time.d.d;
                    }
                } else {
                    if (cCharAt3 != 'D') {
                        throw new IllegalArgumentException("Invalid or unsupported duration ISO non-time unit: " + cCharAt3);
                    }
                    unit = kotlin.time.d.g;
                }
                if (dVar != null && dVar.compareTo(unit) <= 0) {
                    throw new IllegalArgumentException("Unexpected order of duration components");
                }
                int iL = StringsKt.L(strSubstring, '.', 0, false, 6);
                if (unit != kotlin.time.d.d || iL <= 0) {
                    jH = kotlin.time.b.h(jH, g(e(strSubstring), unit));
                } else {
                    String strSubstring2 = strSubstring.substring(0, iL);
                    Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
                    long jH2 = kotlin.time.b.h(jH, g(e(strSubstring2), unit));
                    String strSubstring3 = strSubstring.substring(iL);
                    Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
                    double d = Double.parseDouble(strSubstring3);
                    Intrinsics.checkNotNullParameter(unit, "unit");
                    double dA = kotlin.time.e.a(d, unit, kotlin.time.d.b);
                    if (Double.isNaN(dA)) {
                        throw new IllegalArgumentException("Duration value cannot be NaN.");
                    }
                    long jC = kotlin.math.c.c(dA);
                    jH = kotlin.time.b.h(jH2, (-4611686018426999999L > jC || jC >= 4611686018427000000L) ? c(kotlin.math.c.c(kotlin.time.e.a(d, unit, kotlin.time.d.c))) : d(jC));
                }
                dVar = unit;
                i2 = i4;
            } else {
                if (z2 || (i2 = i2 + 1) == length) {
                    throw new IllegalArgumentException();
                }
                z2 = true;
            }
        }
        return z ? kotlin.time.b.k(jH) : jH;
    }

    public static final long b(long j) {
        long j2 = (j << 1) + 1;
        kotlin.time.a aVar = kotlin.time.b.b;
        int i = kotlin.time.c.a;
        return j2;
    }

    public static final long c(long j) {
        return (-4611686018426L > j || j >= 4611686018427L) ? b(kotlin.ranges.l.d(j, -4611686018427387903L, 4611686018427387903L)) : d(j * 1000000);
    }

    public static final long d(long j) {
        long j2 = j << 1;
        kotlin.time.a aVar = kotlin.time.b.b;
        int i = kotlin.time.c.a;
        return j2;
    }

    public static final long e(String str) {
        int length = str.length();
        int i = (length <= 0 || !StringsKt.F("+-", str.charAt(0), false)) ? 0 : 1;
        if (length - i > 16) {
            Iterable intRange = new IntRange(i, StringsKt.J(str), 1);
            if (!(intRange instanceof Collection) || !((Collection) intRange).isEmpty()) {
                kotlin.ranges.i it2 = intRange.iterator();
                while (it2.c) {
                    char cCharAt = str.charAt(it2.nextInt());
                    if ('0' > cCharAt || cCharAt >= ':') {
                    }
                }
            }
            return str.charAt(0) == '-' ? Long.MIN_VALUE : Long.MAX_VALUE;
        }
        return kotlin.text.D.r(str, "+", false) ? Long.parseLong(kotlin.text.I.A(1, str)) : Long.parseLong(str);
    }

    public static final long f(int i, kotlin.time.d unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        return unit.compareTo(kotlin.time.d.d) <= 0 ? d(kotlin.time.e.c(i, unit, kotlin.time.d.b)) : g(i, unit);
    }

    public static final long g(long j, kotlin.time.d unit) {
        Intrinsics.checkNotNullParameter(unit, "unit");
        kotlin.time.d dVar = kotlin.time.d.b;
        long jC = kotlin.time.e.c(4611686018426999999L, dVar, unit);
        return ((-jC) > j || j > jC) ? b(kotlin.ranges.l.d(kotlin.time.e.b(j, unit, kotlin.time.d.c), -4611686018427387903L, 4611686018427387903L)) : d(kotlin.time.e.c(j, unit, dVar));
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object h(androidx.camera.camera2.internal.s0 r5, androidx.glance.session.x r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            boolean r0 = r7 instanceof androidx.glance.session.N
            if (r0 == 0) goto L13
            r0 = r7
            androidx.glance.session.N r0 = (androidx.glance.session.N) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            androidx.glance.session.N r0 = new androidx.glance.session.N
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L34
            if (r2 != r4) goto L2c
            kotlin.jvm.functions.Function2 r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: androidx.glance.session.TimeoutCancellationException -> L2a
            return r7
        L2a:
            r5 = move-exception
            goto L48
        L2c:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L34:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r6     // Catch: androidx.glance.session.TimeoutCancellationException -> L2a
            r0.l = r4     // Catch: androidx.glance.session.TimeoutCancellationException -> L2a
            androidx.glance.session.M r7 = new androidx.glance.session.M     // Catch: androidx.glance.session.TimeoutCancellationException -> L2a
            r7.<init>(r6, r5, r3)     // Catch: androidx.glance.session.TimeoutCancellationException -> L2a
            java.lang.Object r5 = kotlinx.coroutines.E.m(r7, r0)     // Catch: androidx.glance.session.TimeoutCancellationException -> L2a
            if (r5 != r1) goto L47
            return r1
        L47:
            return r5
        L48:
            int r6 = r6.hashCode()
            int r7 = r5.b
            if (r7 != r6) goto L51
            return r3
        L51:
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1.h(androidx.camera.camera2.internal.s0, androidx.glance.session.x, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
