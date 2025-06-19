package com.google.android.gms.internal.ads;

import android.media.MediaCodecInfo;
import android.os.Build;
import android.text.TextUtils;
import android.view.View;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.RoundingMode;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/* renamed from: com.google.android.gms.internal.ads.es, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2025es {
    public static String b;
    public final /* synthetic */ int a;

    public /* synthetic */ AbstractC2025es(int i) {
        this.a = i;
    }

    public static C2028ev A(com.google.common.util.concurrent.e eVar, Class cls, Fv fv, Executor executor) {
        int i = AbstractRunnableC2116gv.k;
        C2028ev c2028ev = new C2028ev(eVar, cls, fv);
        eVar.a(c2028ev, AbstractC2457os.w(executor, c2028ev));
        return c2028ev;
    }

    public static int B(int i, byte[] bArr, int i2, int i3, C2691uB c2691uB, C2776wA c2776wA) throws zzgzh {
        if ((i >>> 3) == 0) {
            throw new zzgzh("Protocol message contained an invalid tag (zero).");
        }
        int i4 = i & 7;
        if (i4 == 0) {
            int iH = H(bArr, i2, c2776wA);
            c2691uB.c(i, Long.valueOf(c2776wA.b));
            return iH;
        }
        if (i4 == 1) {
            c2691uB.c(i, Long.valueOf(M(i2, bArr)));
            return i2 + 8;
        }
        if (i4 == 2) {
            int iD = D(bArr, i2, c2776wA);
            int i5 = c2776wA.a;
            if (i5 < 0) {
                throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
            }
            if (i5 > bArr.length - iD) {
                throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
            }
            if (i5 == 0) {
                c2691uB.c(i, BA.b);
            } else {
                c2691uB.c(i, BA.w(iD, bArr, i5));
            }
            return iD + i5;
        }
        if (i4 != 3) {
            if (i4 != 5) {
                throw new zzgzh("Protocol message contained an invalid tag (zero).");
            }
            c2691uB.c(i, Integer.valueOf(o(i2, bArr)));
            return i2 + 4;
        }
        int i6 = (i & (-8)) | 4;
        C2691uB c2691uBB = C2691uB.b();
        int i7 = c2776wA.d + 1;
        c2776wA.d = i7;
        if (i7 >= 100) {
            throw new zzgzh("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int i8 = 0;
        while (true) {
            if (i2 >= i3) {
                break;
            }
            int iD2 = D(bArr, i2, c2776wA);
            int i9 = c2776wA.a;
            if (i9 == i6) {
                i8 = i9;
                i2 = iD2;
                break;
            }
            i2 = B(i9, bArr, iD2, i3, c2691uBB, c2776wA);
            i8 = i9;
        }
        c2776wA.d--;
        if (i2 > i3 || i8 != i6) {
            throw new zzgzh("Failed to parse the message.");
        }
        c2691uB.c(i, c2691uBB);
        return i2;
    }

    public static Sv C(Throwable th) {
        th.getClass();
        Sv sv = new Sv();
        sv.h(th);
        return sv;
    }

    public static int D(byte[] bArr, int i, C2776wA c2776wA) {
        int i2 = i + 1;
        byte b2 = bArr[i];
        if (b2 < 0) {
            return F(b2, bArr, i2, c2776wA);
        }
        c2776wA.a = b2;
        return i2;
    }

    public static Tv E(Object obj) {
        return obj == null ? Tv.b : new Tv(obj);
    }

    public static int F(int i, byte[] bArr, int i2, C2776wA c2776wA) {
        byte b2 = bArr[i2];
        int i3 = i2 + 1;
        int i4 = i & 127;
        if (b2 >= 0) {
            c2776wA.a = i4 | (b2 << 7);
            return i3;
        }
        int i5 = i4 | ((b2 & Byte.MAX_VALUE) << 7);
        int i6 = i2 + 2;
        byte b3 = bArr[i3];
        if (b3 >= 0) {
            c2776wA.a = i5 | (b3 << 14);
            return i6;
        }
        int i7 = i5 | ((b3 & Byte.MAX_VALUE) << 14);
        int i8 = i2 + 3;
        byte b4 = bArr[i6];
        if (b4 >= 0) {
            c2776wA.a = i7 | (b4 << 21);
            return i8;
        }
        int i9 = i7 | ((b4 & Byte.MAX_VALUE) << 21);
        int i10 = i2 + 4;
        byte b5 = bArr[i8];
        if (b5 >= 0) {
            c2776wA.a = i9 | (b5 << 28);
            return i10;
        }
        int i11 = i9 | ((b5 & Byte.MAX_VALUE) << 28);
        while (true) {
            int i12 = i10 + 1;
            if (bArr[i10] >= 0) {
                c2776wA.a = i11;
                return i12;
            }
            i10 = i12;
        }
    }

    public static int G(int i, byte[] bArr, int i2, int i3, VA va, C2776wA c2776wA) {
        PA pa = (PA) va;
        int iD = D(bArr, i2, c2776wA);
        pa.e(c2776wA.a);
        while (iD < i3) {
            int iD2 = D(bArr, iD, c2776wA);
            if (i != c2776wA.a) {
                break;
            }
            iD = D(bArr, iD2, c2776wA);
            pa.e(c2776wA.a);
        }
        return iD;
    }

    public static int H(byte[] bArr, int i, C2776wA c2776wA) {
        long j = bArr[i];
        int i2 = i + 1;
        if (j >= 0) {
            c2776wA.b = j;
            return i2;
        }
        int i3 = i + 2;
        byte b2 = bArr[i2];
        long j2 = (j & 127) | ((b2 & Byte.MAX_VALUE) << 7);
        int i4 = 7;
        while (b2 < 0) {
            int i5 = i3 + 1;
            i4 += 7;
            j2 |= (r10 & Byte.MAX_VALUE) << i4;
            b2 = bArr[i3];
            i3 = i5;
        }
        c2776wA.b = j2;
        return i3;
    }

    public static RunnableFutureC2161hw I(Ev ev, Xv xv) {
        RunnableFutureC2161hw runnableFutureC2161hw = new RunnableFutureC2161hw();
        runnableFutureC2161hw.h = new C2117gw(runnableFutureC2161hw, ev);
        xv.execute(runnableFutureC2161hw);
        return runnableFutureC2161hw;
    }

    public static int J(Object obj, InterfaceC2562rB interfaceC2562rB, byte[] bArr, int i, int i2, int i3, C2776wA c2776wA) throws zzgzh {
        C2089gB c2089gB = (C2089gB) interfaceC2562rB;
        int i4 = c2776wA.d + 1;
        c2776wA.d = i4;
        if (i4 >= 100) {
            throw new zzgzh("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int iZ = c2089gB.z(obj, bArr, i, i2, i3, c2776wA);
        c2776wA.d--;
        c2776wA.c = obj;
        return iZ;
    }

    public static int K(Object obj, InterfaceC2562rB interfaceC2562rB, byte[] bArr, int i, int i2, C2776wA c2776wA) throws zzgzh {
        int iF = i + 1;
        int i3 = bArr[i];
        if (i3 < 0) {
            iF = F(i3, bArr, iF, c2776wA);
            i3 = c2776wA.a;
        }
        int i4 = iF;
        if (i3 < 0 || i3 > i2 - i4) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        int i5 = c2776wA.d + 1;
        c2776wA.d = i5;
        if (i5 >= 100) {
            throw new zzgzh("Protocol message had too many levels of nesting.  May be malicious.  Use setRecursionLimit() to increase the recursion depth limit.");
        }
        int i6 = i4 + i3;
        interfaceC2562rB.c(obj, bArr, i4, i6, c2776wA);
        c2776wA.d--;
        c2776wA.c = obj;
        return i6;
    }

    public static C2889yv L(com.google.common.util.concurrent.e eVar, InterfaceC2544qt interfaceC2544qt, Executor executor) {
        int i = AbstractRunnableC2932zv.j;
        C2889yv c2889yv = new C2889yv(eVar, interfaceC2544qt);
        eVar.a(c2889yv, AbstractC2457os.w(executor, c2889yv));
        return c2889yv;
    }

    public static long M(int i, byte[] bArr) {
        return (bArr[i] & 255) | ((bArr[i + 1] & 255) << 8) | ((bArr[i + 2] & 255) << 16) | ((bArr[i + 3] & 255) << 24) | ((bArr[i + 4] & 255) << 32) | ((bArr[i + 5] & 255) << 40) | ((bArr[i + 6] & 255) << 48) | ((bArr[i + 7] & 255) << 56);
    }

    public static C2846xv N(com.google.common.util.concurrent.e eVar, Fv fv, Executor executor) {
        int i = AbstractRunnableC2932zv.j;
        C2846xv c2846xv = new C2846xv(eVar, fv);
        eVar.a(c2846xv, AbstractC2457os.w(executor, c2846xv));
        return c2846xv;
    }

    public static com.google.common.util.concurrent.e O(com.google.common.util.concurrent.e eVar, long j, TimeUnit timeUnit, ScheduledExecutorService scheduledExecutorService) {
        if (eVar.isDone()) {
            return eVar;
        }
        C2073fw c2073fw = new C2073fw();
        c2073fw.h = eVar;
        RunnableC2104gj runnableC2104gj = new RunnableC2104gj();
        runnableC2104gj.b = c2073fw;
        c2073fw.i = scheduledExecutorService.schedule(runnableC2104gj, j, timeUnit);
        eVar.a(runnableC2104gj, Kv.a);
        return c2073fw;
    }

    public static Object P(Future future) {
        if (future.isDone()) {
            return AbstractC2543qs.d(future);
        }
        throw new IllegalStateException(r("Future was expected to be done: %s", future));
    }

    public static Object Q(C2313ld c2313ld) {
        try {
            return AbstractC2543qs.d(c2313ld);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof Error) {
                throw new Lv((Error) e.getCause());
            }
            throw new zzgea(e.getCause());
        }
    }

    public static byte d(long j) {
        AbstractC1981ds.I("out of range: %s", j, (j >> 8) == 0);
        return (byte) j;
    }

    public static int e(int i, int i2) {
        long j = i + i2;
        int i3 = (int) j;
        if (j == i3) {
            return i3;
        }
        throw new ArithmeticException(android.support.v4.media.session.a.j("overflow: checkedAdd(", i, ", ", ")", i2));
    }

    public static int f(byte[] bArr, int i, C2776wA c2776wA) throws zzgzh {
        int iD = D(bArr, i, c2776wA);
        int i2 = c2776wA.a;
        if (i2 < 0) {
            throw new zzgzh("CodedInputStream encountered an embedded string or message which claimed to have negative size.");
        }
        if (i2 > bArr.length - iD) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
        if (i2 == 0) {
            c2776wA.c = BA.b;
            return iD;
        }
        c2776wA.c = BA.w(iD, bArr, i2);
        return iD + i2;
    }

    /* JADX WARN: Removed duplicated region for block: B:43:0x00c2  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00c5 A[EDGE_INSN: B:66:0x00c5->B:44:0x00c5 BREAK  A[LOOP:1: B:29:0x0094->B:67:0x0094]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String i(android.content.Context r10) {
        /*
            java.lang.String r0 = com.google.android.gms.internal.ads.AbstractC2025es.b
            if (r0 == 0) goto L5
            return r0
        L5:
            android.content.pm.PackageManager r0 = r10.getPackageManager()
            android.content.Intent r1 = new android.content.Intent
            java.lang.String r2 = "android.intent.action.VIEW"
            java.lang.String r3 = "https://www.example.com"
            android.net.Uri r3 = android.net.Uri.parse(r3)
            r1.<init>(r2, r3)
            r2 = 0
            android.content.pm.ResolveInfo r3 = r0.resolveActivity(r1, r2)
            r4 = 0
            if (r3 == 0) goto L23
            android.content.pm.ActivityInfo r3 = r3.activityInfo
            java.lang.String r3 = r3.packageName
            goto L24
        L23:
            r3 = r4
        L24:
            java.util.List r5 = r0.queryIntentActivities(r1, r2)
            java.util.ArrayList r6 = new java.util.ArrayList
            r6.<init>()
            java.util.Iterator r5 = r5.iterator()
        L31:
            boolean r7 = r5.hasNext()
            if (r7 == 0) goto L5c
            java.lang.Object r7 = r5.next()
            android.content.pm.ResolveInfo r7 = (android.content.pm.ResolveInfo) r7
            android.content.Intent r8 = new android.content.Intent
            r8.<init>()
            java.lang.String r9 = "android.support.customtabs.action.CustomTabsService"
            r8.setAction(r9)
            android.content.pm.ActivityInfo r9 = r7.activityInfo
            java.lang.String r9 = r9.packageName
            r8.setPackage(r9)
            android.content.pm.ResolveInfo r8 = r0.resolveService(r8, r2)
            if (r8 == 0) goto L31
            android.content.pm.ActivityInfo r7 = r7.activityInfo
            java.lang.String r7 = r7.packageName
            r6.add(r7)
            goto L31
        L5c:
            boolean r0 = r6.isEmpty()
            if (r0 == 0) goto L66
            com.google.android.gms.internal.ads.AbstractC2025es.b = r4
            goto Le5
        L66:
            int r0 = r6.size()
            r4 = 1
            if (r0 != r4) goto L77
            java.lang.Object r10 = r6.get(r2)
            java.lang.String r10 = (java.lang.String) r10
            com.google.android.gms.internal.ads.AbstractC2025es.b = r10
            goto Le5
        L77:
            boolean r0 = android.text.TextUtils.isEmpty(r3)
            if (r0 != 0) goto Lc5
            android.content.pm.PackageManager r10 = r10.getPackageManager()     // Catch: java.lang.RuntimeException -> Lb5
            r0 = 64
            java.util.List r10 = r10.queryIntentActivities(r1, r0)     // Catch: java.lang.RuntimeException -> Lb5
            if (r10 == 0) goto Lbc
            int r0 = r10.size()     // Catch: java.lang.RuntimeException -> Lb5
            if (r0 != 0) goto L90
            goto Lbc
        L90:
            java.util.Iterator r10 = r10.iterator()     // Catch: java.lang.RuntimeException -> Lb5
        L94:
            boolean r0 = r10.hasNext()     // Catch: java.lang.RuntimeException -> Lb5
            if (r0 == 0) goto Lbc
            java.lang.Object r0 = r10.next()     // Catch: java.lang.RuntimeException -> Lb5
            android.content.pm.ResolveInfo r0 = (android.content.pm.ResolveInfo) r0     // Catch: java.lang.RuntimeException -> Lb5
            android.content.IntentFilter r1 = r0.filter     // Catch: java.lang.RuntimeException -> Lb5
            if (r1 == 0) goto L94
            int r2 = r1.countDataAuthorities()     // Catch: java.lang.RuntimeException -> Lb5
            if (r2 == 0) goto L94
            int r1 = r1.countDataPaths()     // Catch: java.lang.RuntimeException -> Lb5
            if (r1 == 0) goto L94
            android.content.pm.ActivityInfo r0 = r0.activityInfo     // Catch: java.lang.RuntimeException -> Lb5
            if (r0 == 0) goto L94
            goto Lc5
        Lb5:
            java.lang.String r10 = "CustomTabsHelper"
            java.lang.String r0 = "Runtime exception while getting specialized handlers"
            android.util.Log.e(r10, r0)
        Lbc:
            boolean r10 = r6.contains(r3)
            if (r10 == 0) goto Lc5
            com.google.android.gms.internal.ads.AbstractC2025es.b = r3
            goto Le5
        Lc5:
            java.lang.String r10 = "com.android.chrome"
            boolean r0 = r6.contains(r10)
            if (r0 == 0) goto Ld0
            com.google.android.gms.internal.ads.AbstractC2025es.b = r10
            goto Le5
        Ld0:
            java.lang.String r10 = "com.chrome.beta"
            boolean r0 = r6.contains(r10)
            if (r0 == 0) goto Ldb
            com.google.android.gms.internal.ads.AbstractC2025es.b = r10
            goto Le5
        Ldb:
            java.lang.String r10 = "com.chrome.dev"
            boolean r0 = r6.contains(r10)
            if (r0 == 0) goto Le5
            com.google.android.gms.internal.ads.AbstractC2025es.b = r10
        Le5:
            java.lang.String r10 = com.google.android.gms.internal.ads.AbstractC2025es.b
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC2025es.i(android.content.Context):java.lang.String");
    }

    public static String j(View view) {
        if (!view.isAttachedToWindow()) {
            return "notAttached";
        }
        int visibility = view.getVisibility();
        if (visibility == 8) {
            return "viewGone";
        }
        if (visibility == 4) {
            return "viewInvisible";
        }
        if (visibility != 0) {
            return "viewNotVisible";
        }
        if (view.getAlpha() == DefinitionKt.NO_Float_VALUE) {
            return "viewAlphaZero";
        }
        return null;
    }

    public static Date k(long j) {
        return new Date((j - 2082844800) * 1000);
    }

    public static void l(File file, boolean z) {
        if (z && file.exists() && !file.isDirectory()) {
            file.delete();
        }
        if (file.exists()) {
            return;
        }
        file.mkdirs();
    }

    public static byte[] m(byte[] bArr) {
        if (bArr.length != 16) {
            throw new IllegalArgumentException("value must be a block.");
        }
        byte[] bArr2 = new byte[16];
        int i = 0;
        while (i < 16) {
            int i2 = i + 1;
            byte b2 = bArr[i];
            byte b3 = (byte) ((b2 + b2) & 254);
            bArr2[i] = b3;
            if (i < 15) {
                bArr2[i] = (byte) (((bArr[i2] >> 7) & 1) | b3);
            }
            i = i2;
        }
        bArr2[15] = (byte) (((byte) ((bArr[0] >> 7) & 135)) ^ bArr2[15]);
        return bArr2;
    }

    public static int n(int i, int i2) {
        RoundingMode roundingMode = RoundingMode.CEILING;
        roundingMode.getClass();
        if (i2 == 0) {
            throw new ArithmeticException("/ by zero");
        }
        int i3 = i / i2;
        int i4 = i - (i2 * i3);
        if (i4 == 0) {
            return i3;
        }
        int i5 = ((i ^ i2) >> 31) | 1;
        switch (Zu.a[roundingMode.ordinal()]) {
            case 1:
                AbstractC2543qs.q(false);
                return i3;
            case 2:
                return i3;
            case 3:
                if (i5 >= 0) {
                    return i3;
                }
                break;
            case 4:
                break;
            case 5:
                if (i5 <= 0) {
                    return i3;
                }
                break;
            case 6:
            case 7:
            case 8:
                int iAbs = Math.abs(i4);
                int iAbs2 = iAbs - (Math.abs(i2) - iAbs);
                if (iAbs2 == 0) {
                    RoundingMode roundingMode2 = RoundingMode.HALF_UP;
                    RoundingMode roundingMode3 = RoundingMode.HALF_EVEN;
                    return i3;
                }
                if (iAbs2 <= 0) {
                    return i3;
                }
                break;
            default:
                throw new AssertionError();
        }
        return i3 + i5;
    }

    public static int o(int i, byte[] bArr) {
        int i2 = bArr[i] & 255;
        int i3 = bArr[i + 1] & 255;
        int i4 = bArr[i + 2] & 255;
        return ((bArr[i + 3] & 255) << 24) | (i3 << 8) | i2 | (i4 << 16);
    }

    public static int p(boolean z) {
        MediaCodecInfo.VideoCapabilities videoCapabilities;
        List supportedPerformancePoints;
        try {
            EF ef = new EF();
            ef.d("video/avc");
            C1832aG c1832aG = new C1832aG(ef);
            if (c1832aG.m != null) {
                Bu buC = ME.c(C1.n, c1832aG, z, false);
                for (int i = 0; i < buC.d; i++) {
                    if (((HE) buC.get(i)).d != null && (videoCapabilities = ((HE) buC.get(i)).d.getVideoCapabilities()) != null && (supportedPerformancePoints = videoCapabilities.getSupportedPerformancePoints()) != null && !supportedPerformancePoints.isEmpty()) {
                        com.bumptech.glide.load.model.stream.g.n();
                        MediaCodecInfo.VideoCapabilities.PerformancePoint performancePointH = com.bumptech.glide.load.model.stream.g.h();
                        for (int i2 = 0; i2 < supportedPerformancePoints.size(); i2++) {
                            if (com.bumptech.glide.load.model.stream.g.j(supportedPerformancePoints.get(i2)).covers(performancePointH)) {
                                return 2;
                            }
                        }
                        return 1;
                    }
                }
            }
        } catch (zztq unused) {
        }
        return 0;
    }

    public static File q(String str, String str2, File file) {
        if (TextUtils.isEmpty(str) || TextUtils.isEmpty(str2)) {
            return null;
        }
        return new File(t(file, str), str2);
    }

    public static String r(String str, Object... objArr) {
        int length;
        int length2;
        int iIndexOf;
        String strE;
        int i = 0;
        int i2 = 0;
        while (true) {
            length = objArr.length;
            if (i2 >= length) {
                break;
            }
            Object obj = objArr[i2];
            if (obj == null) {
                strE = "null";
            } else {
                try {
                    strE = obj.toString();
                } catch (Exception e) {
                    String strL = android.support.v4.media.session.a.l(obj.getClass().getName(), "@", Integer.toHexString(System.identityHashCode(obj)));
                    Logger.getLogger("com.google.common.base.Strings").logp(Level.WARNING, "com.google.common.base.Strings", "lenientToString", "Exception during lenientFormat for ".concat(strL), (Throwable) e);
                    strE = AbstractC0147y.e(SimpleComparison.LESS_THAN_OPERATION, strL, " threw ", e.getClass().getName(), SimpleComparison.GREATER_THAN_OPERATION);
                }
            }
            objArr[i2] = strE;
            i2++;
        }
        StringBuilder sb = new StringBuilder(str.length() + (length * 16));
        int i3 = 0;
        while (true) {
            length2 = objArr.length;
            if (i >= length2 || (iIndexOf = str.indexOf("%s", i3)) == -1) {
                break;
            }
            sb.append((CharSequence) str, i3, iIndexOf);
            sb.append(objArr[i]);
            i++;
            i3 = iIndexOf + 2;
        }
        sb.append((CharSequence) str, i3, str.length());
        if (i < length2) {
            sb.append(" [");
            sb.append(objArr[i]);
            for (int i4 = i + 1; i4 < objArr.length; i4++) {
                sb.append(", ");
                sb.append(objArr[i4]);
            }
            sb.append(']');
        }
        return sb.toString();
    }

    public static boolean s(Object obj, Map map) {
        if (map == obj) {
            return true;
        }
        if (obj instanceof Map) {
            return map.entrySet().equals(((Map) obj).entrySet());
        }
        return false;
    }

    public static File t(File file, String str) {
        if (TextUtils.isEmpty(str)) {
            return null;
        }
        File file2 = new File(file, str);
        l(file2, false);
        return file2;
    }

    public static final void u(StringBuilder sb, Iterator it2, String str) {
        try {
            if (it2.hasNext()) {
                Object next = it2.next();
                Objects.requireNonNull(next);
                sb.append(next instanceof CharSequence ? (CharSequence) next : next.toString());
                while (it2.hasNext()) {
                    sb.append((CharSequence) str);
                    Object next2 = it2.next();
                    Objects.requireNonNull(next2);
                    sb.append(next2 instanceof CharSequence ? (CharSequence) next2 : next2.toString());
                }
            }
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    public static boolean v(File file) {
        boolean z;
        if (!file.exists()) {
            return true;
        }
        File[] fileArrListFiles = file.listFiles();
        if (fileArrListFiles != null) {
            z = true;
            for (int i = 0; i < fileArrListFiles.length; i++) {
                File file2 = fileArrListFiles[i];
                z = file2 != null && v(file2) && z;
            }
        } else {
            z = true;
        }
        return file.delete() && z;
    }

    public static int w(InterfaceC2562rB interfaceC2562rB, int i, byte[] bArr, int i2, int i3, VA va, C2776wA c2776wA) throws zzgzh {
        OA oaZze = interfaceC2562rB.zze();
        InterfaceC2562rB interfaceC2562rB2 = interfaceC2562rB;
        byte[] bArr2 = bArr;
        int i4 = i3;
        C2776wA c2776wA2 = c2776wA;
        int iK = K(oaZze, interfaceC2562rB2, bArr2, i2, i4, c2776wA2);
        interfaceC2562rB2.a(oaZze);
        c2776wA2.c = oaZze;
        va.add(oaZze);
        while (iK < i4) {
            C2776wA c2776wA3 = c2776wA2;
            int i5 = i4;
            int iD = D(bArr2, iK, c2776wA3);
            if (i != c2776wA3.a) {
                break;
            }
            byte[] bArr3 = bArr2;
            InterfaceC2562rB interfaceC2562rB3 = interfaceC2562rB2;
            OA oaZze2 = interfaceC2562rB3.zze();
            iK = K(oaZze2, interfaceC2562rB3, bArr3, iD, i5, c2776wA3);
            interfaceC2562rB2 = interfaceC2562rB3;
            bArr2 = bArr3;
            i4 = i5;
            c2776wA2 = c2776wA3;
            interfaceC2562rB2.a(oaZze2);
            c2776wA2.c = oaZze2;
            va.add(oaZze2);
        }
        return iK;
    }

    public static C2072fv x(com.google.common.util.concurrent.e eVar, Class cls, InterfaceC2544qt interfaceC2544qt, Xv xv) {
        int i = AbstractRunnableC2116gv.k;
        C2072fv c2072fv = new C2072fv(eVar, cls, interfaceC2544qt);
        eVar.a(c2072fv, AbstractC2457os.w(xv, c2072fv));
        return c2072fv;
    }

    public static boolean y(File file, byte[] bArr) throws Throwable {
        FileOutputStream fileOutputStream = null;
        try {
            FileOutputStream fileOutputStream2 = new FileOutputStream(file);
            try {
                if (Build.VERSION.SDK_INT >= 34) {
                    file.setReadOnly();
                }
                fileOutputStream2.write(bArr);
                fileOutputStream2.flush();
                com.google.android.gms.common.util.c.d(fileOutputStream2);
                return true;
            } catch (IOException unused) {
                fileOutputStream = fileOutputStream2;
                com.google.android.gms.common.util.c.d(fileOutputStream);
                return false;
            } catch (Throwable th) {
                th = th;
                fileOutputStream = fileOutputStream2;
                com.google.android.gms.common.util.c.d(fileOutputStream);
                throw th;
            }
        } catch (IOException unused2) {
        } catch (Throwable th2) {
            th = th2;
        }
    }

    public static int z(byte[] bArr, int i, VA va, C2776wA c2776wA) throws zzgzh {
        PA pa = (PA) va;
        int iD = D(bArr, i, c2776wA);
        int i2 = c2776wA.a + iD;
        while (iD < i2) {
            iD = D(bArr, iD, c2776wA);
            pa.e(c2776wA.a);
        }
        if (iD == i2) {
            return iD;
        }
        throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
    }

    public abstract AbstractC2547qw g();

    public abstract Object h();

    public String toString() {
        switch (this.a) {
            case 4:
                return h().toString();
            default:
                return super.toString();
        }
    }
}
