package com.google.android.gms.internal.ads;

import android.app.UiModeManager;
import android.content.Context;
import android.hardware.display.DisplayManager;
import android.media.MediaFormat;
import android.opengl.EGL14;
import android.os.RemoteException;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Pair;
import android.view.Display;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.ads.internal.client.zze;
import com.google.android.gms.tasks.Task;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.di, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1972di {
    public static Task I;
    public static com.google.android.gms.internal.appset.g J;
    public static UiModeManager N;
    public static ExecutorService b;
    public final /* synthetic */ int a = 21;
    public static final int[] c = {com.pubmatic.sdk.common.h.AD_NOT_READY, 2000, 1920, 1601, 1600, 1001, 1000, 960, 800, 800, DtbConstants.DEFAULT_PLAYER_HEIGHT, 400, 400, 2048};
    public static final C1 d = new C1(17);
    public static final I3 e = new I3("gads:afs:csa:experiment_id", 4, "");
    public static final I3 f = new I3("gads:app_index:experiment_id", 4, "");
    public static final I3 g = new I3("gads:block_autoclicks_experiment_id", 4, "");
    public static final I3 h = new I3("gads:sdk_core_experiment_id", 4, "");
    public static final I3 i = new I3("gads:spam_app_context:experiment_id", 4, "");
    public static final I3 j = new I3("gads:temporary_experiment_id:1", 4, "");
    public static final I3 k = new I3("gads:temporary_experiment_id:10", 4, "");
    public static final I3 l = new I3("gads:temporary_experiment_id:11", 4, "");
    public static final I3 m = new I3("gads:temporary_experiment_id:12", 4, "");
    public static final I3 n = new I3("gads:temporary_experiment_id:13", 4, "");
    public static final I3 o = new I3("gads:temporary_experiment_id:14", 4, "");
    public static final I3 p = new I3("gads:temporary_experiment_id:15", 4, "");
    public static final I3 q = new I3("gads:temporary_experiment_id:2", 4, "");
    public static final I3 r = new I3("gads:temporary_experiment_id:3", 4, "");
    public static final I3 s = new I3("gads:temporary_experiment_id:4", 4, "");
    public static final I3 t = new I3("gads:temporary_experiment_id:5", 4, "");
    public static final I3 u = new I3("gads:temporary_experiment_id:6", 4, "");
    public static final I3 v = new I3("gads:temporary_experiment_id:7", 4, "");
    public static final I3 w = new I3("gads:temporary_experiment_id:8", 4, "");
    public static final I3 x = new I3("gads:temporary_experiment_id:9", 4, "");
    public static final I3 y = new I3("gads:corewebview:experiment_id", 4, "");
    public static final H5 z = new H5(9);
    public static final H5 A = new H5(13);
    public static final H5 B = new H5(25);
    public static final H5 C = new H5(29);
    public static final C2016ej D = new C2016ej(7);
    public static final C2016ej E = new C2016ej(12);
    public static final C2016ej F = new C2016ej(16);
    public static final C2016ej G = new C2016ej(19);
    public static final C2016ej H = new C2016ej(28);
    public static final Object K = new Object();
    public static final C2240jq L = new C2240jq(6);
    public static final androidx.camera.camera2.internal.compat.workaround.e M = new androidx.camera.camera2.internal.compat.workaround.e(8, false);

    public static int A(int i2, Kn kn) {
        byte[] bArr = kn.a;
        int i3 = kn.b;
        int i4 = i3;
        while (true) {
            int i5 = i4 + 1;
            if (i5 >= i3 + i2) {
                return i2;
            }
            if ((bArr[i4] & 255) == 255 && bArr[i5] == 0) {
                System.arraycopy(bArr, i4 + 2, bArr, i5, (i2 - (i4 - i3)) - 2);
                i2--;
            }
            i4 = i5;
        }
    }

    public static void B(C2466p0 c2466p0) {
        int iF;
        int iF2 = c2466p0.f(2);
        if (iF2 == 0) {
            c2466p0.u(6);
            return;
        }
        int iS = s(c2466p0, 5, 8, 16) + 1;
        if (iF2 == 1) {
            c2466p0.u(iS * 7);
            return;
        }
        if (iF2 == 2) {
            boolean zW = c2466p0.w();
            int i2 = true != zW ? 5 : 1;
            int i3 = true == zW ? 7 : 5;
            int i4 = true == zW ? 8 : 6;
            int i5 = 0;
            while (i5 < iS) {
                if (c2466p0.w()) {
                    c2466p0.u(7);
                    iF = 0;
                } else {
                    if (c2466p0.f(2) == 3 && c2466p0.f(i3) * i2 != 0) {
                        c2466p0.t();
                    }
                    iF = c2466p0.f(i4) * i2;
                    if (iF != 0 && iF != 180) {
                        c2466p0.t();
                    }
                    c2466p0.t();
                }
                if (iF != 0 && iF != 180 && c2466p0.w()) {
                    i5++;
                }
                i5++;
            }
        }
    }

    public static void C(C2466p0 c2466p0, G g2) throws zzaz {
        c2466p0.u(2);
        boolean zW = c2466p0.w();
        int iF = c2466p0.f(8);
        for (int i2 = 0; i2 < iF; i2++) {
            c2466p0.u(2);
            if (c2466p0.w()) {
                c2466p0.u(5);
            }
            if (zW) {
                c2466p0.u(24);
            } else {
                if (c2466p0.w()) {
                    if (!c2466p0.w()) {
                        c2466p0.u(4);
                    }
                    g2.c = c2466p0.f(6) + 1;
                }
                c2466p0.u(4);
            }
        }
        if (c2466p0.w()) {
            c2466p0.u(3);
            if (c2466p0.w()) {
                F(c2466p0);
            }
        }
    }

    public static Pair D(RandomAccessFile randomAccessFile, int i2) throws IOException {
        int i3;
        long length = randomAccessFile.length();
        if (length < 22) {
            return null;
        }
        ByteBuffer byteBufferAllocate = ByteBuffer.allocate(((int) Math.min(i2, (-22) + length)) + 22);
        byteBufferAllocate.order(ByteOrder.LITTLE_ENDIAN);
        long jCapacity = length - byteBufferAllocate.capacity();
        randomAccessFile.seek(jCapacity);
        randomAccessFile.readFully(byteBufferAllocate.array(), byteBufferAllocate.arrayOffset(), byteBufferAllocate.capacity());
        I(byteBufferAllocate);
        int iCapacity = byteBufferAllocate.capacity();
        if (iCapacity < 22) {
            i3 = -1;
        } else {
            int i4 = iCapacity - 22;
            int iMin = Math.min(i4, 65535);
            for (int i5 = 0; i5 < iMin; i5++) {
                i3 = i4 - i5;
                if (byteBufferAllocate.getInt(i3) == 101010256 && ((char) byteBufferAllocate.getShort(i3 + 20)) == i5) {
                    break;
                }
            }
            i3 = -1;
        }
        if (i3 == -1) {
            return null;
        }
        byteBufferAllocate.position(i3);
        ByteBuffer byteBufferSlice = byteBufferAllocate.slice();
        byteBufferSlice.order(ByteOrder.LITTLE_ENDIAN);
        return Pair.create(byteBufferSlice, Long.valueOf(jCapacity + i3));
    }

    public static Bu E(int i2, byte[] bArr, int i3) {
        if (i3 >= bArr.length) {
            return AbstractC2330lu.s("");
        }
        C2244ju c2244ju = AbstractC2330lu.b;
        AbstractC2543qs.g(4, "initialCapacity");
        Object[] objArrCopyOf = new Object[4];
        int iR = r(i3, bArr, i2);
        int i4 = 0;
        while (i3 < iR) {
            String str = new String(bArr, i3, iR - i3, K(i2));
            int length = objArrCopyOf.length;
            int i5 = i4 + 1;
            int iH = AbstractC2027eu.h(length, i5);
            if (iH > length) {
                objArrCopyOf = Arrays.copyOf(objArrCopyOf, iH);
            }
            objArrCopyOf[i4] = str;
            i3 = j(i2) + iR;
            iR = r(i3, bArr, i2);
            i4 = i5;
        }
        Bu buM = AbstractC2330lu.m(i4, objArrCopyOf);
        return buM.isEmpty() ? AbstractC2330lu.s("") : buM;
    }

    public static void F(C2466p0 c2466p0) throws zzaz {
        int iF = c2466p0.f(6);
        if (iF < 2 || iF > 42) {
            throw zzaz.b(String.format("Invalid language tag bytes number: %d. Must be between 2 and 42.", Integer.valueOf(iF)));
        }
        c2466p0.u(iF * 8);
    }

    public static boolean G(String str) {
        String strEglQueryString = EGL14.eglQueryString(EGL14.eglGetDisplay(0), 12373);
        return strEglQueryString != null && strEglQueryString.contains(str);
    }

    public static String H(byte[] bArr, int i2, int i3, Charset charset) {
        return (i3 <= i2 || i3 > bArr.length) ? "" : new String(bArr, i2, i3 - i2, charset);
    }

    public static void I(ByteBuffer byteBuffer) {
        if (byteBuffer.order() != ByteOrder.LITTLE_ENDIAN) {
            throw new IllegalArgumentException("ByteBuffer byte order must be little endian");
        }
    }

    public static String J(int i2, int i3, int i4, int i5, int i6) {
        return i2 == 2 ? String.format(Locale.US, "%c%c%c", Integer.valueOf(i3), Integer.valueOf(i4), Integer.valueOf(i5)) : String.format(Locale.US, "%c%c%c%c", Integer.valueOf(i3), Integer.valueOf(i4), Integer.valueOf(i5), Integer.valueOf(i6));
    }

    public static Charset K(int i2) {
        return i2 != 1 ? i2 != 2 ? i2 != 3 ? StandardCharsets.ISO_8859_1 : StandardCharsets.UTF_8 : StandardCharsets.UTF_16BE : StandardCharsets.UTF_16;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x006b A[Catch: all -> 0x0020, TryCatch #0 {all -> 0x0020, blocks: (B:3:0x0006, B:7:0x0013, B:20:0x003e, B:23:0x0049, B:25:0x006b, B:29:0x0071, B:41:0x008d, B:42:0x008f, B:45:0x0095, B:48:0x009f, B:31:0x007b, B:35:0x0082, B:10:0x0023), top: B:54:0x0006 }] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0079  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x008d A[Catch: all -> 0x0020, TryCatch #0 {all -> 0x0020, blocks: (B:3:0x0006, B:7:0x0013, B:20:0x003e, B:23:0x0049, B:25:0x006b, B:29:0x0071, B:41:0x008d, B:42:0x008f, B:45:0x0095, B:48:0x009f, B:31:0x007b, B:35:0x0082, B:10:0x0023), top: B:54:0x0006 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean L(com.google.android.gms.internal.ads.Kn r21, int r22, int r23, boolean r24) {
        /*
            r1 = r21
            r0 = r22
            int r2 = r1.b
        L6:
            int r3 = r1.s()     // Catch: java.lang.Throwable -> L20
            r4 = 1
            r5 = r23
            if (r3 < r5) goto La5
            r3 = 3
            r6 = 0
            if (r0 < r3) goto L23
            int r7 = r1.u()     // Catch: java.lang.Throwable -> L20
            long r8 = r1.H()     // Catch: java.lang.Throwable -> L20
            int r10 = r1.D()     // Catch: java.lang.Throwable -> L20
            goto L2d
        L20:
            r0 = move-exception
            goto La9
        L23:
            int r7 = r1.B()     // Catch: java.lang.Throwable -> L20
            int r8 = r1.B()     // Catch: java.lang.Throwable -> L20
            long r8 = (long) r8     // Catch: java.lang.Throwable -> L20
            r10 = r6
        L2d:
            r11 = 0
            if (r7 != 0) goto L39
            int r7 = (r8 > r11 ? 1 : (r8 == r11 ? 0 : -1))
            if (r7 != 0) goto L39
            if (r10 != 0) goto L39
            goto La5
        L39:
            r7 = 4
            if (r0 != r7) goto L69
            if (r24 != 0) goto L69
            r13 = 8421504(0x808080, double:4.160776E-317)
            long r13 = r13 & r8
            int r11 = (r13 > r11 ? 1 : (r13 == r11 ? 0 : -1))
            if (r11 == 0) goto L49
        L46:
            r4 = r6
            goto La5
        L49:
            r11 = 255(0xff, double:1.26E-321)
            long r13 = r8 & r11
            r15 = 8
            long r15 = r8 >> r15
            r17 = 16
            long r17 = r8 >> r17
            r19 = 24
            long r8 = r8 >> r19
            long r15 = r15 & r11
            long r11 = r17 & r11
            r17 = 7
            long r15 = r15 << r17
            long r13 = r13 | r15
            r15 = 14
            long r11 = r11 << r15
            long r11 = r11 | r13
            r13 = 21
            long r8 = r8 << r13
            long r8 = r8 | r11
        L69:
            if (r0 != r7) goto L79
            r3 = r10 & 64
            if (r3 == 0) goto L70
            goto L71
        L70:
            r4 = r6
        L71:
            r3 = r10 & 1
            r20 = r4
            r4 = r3
            r3 = r20
            goto L8b
        L79:
            if (r0 != r3) goto L89
            r3 = r10 & 32
            if (r3 == 0) goto L81
            r3 = r4
            goto L82
        L81:
            r3 = r6
        L82:
            r7 = r10 & 128(0x80, float:1.8E-43)
            if (r7 == 0) goto L87
            goto L8b
        L87:
            r4 = r6
            goto L8b
        L89:
            r3 = r6
            r4 = r3
        L8b:
            if (r4 == 0) goto L8f
            int r3 = r3 + 4
        L8f:
            long r3 = (long) r3     // Catch: java.lang.Throwable -> L20
            int r3 = (r8 > r3 ? 1 : (r8 == r3 ? 0 : -1))
            if (r3 >= 0) goto L95
            goto L46
        L95:
            int r3 = r1.s()     // Catch: java.lang.Throwable -> L20
            long r3 = (long) r3     // Catch: java.lang.Throwable -> L20
            int r3 = (r3 > r8 ? 1 : (r3 == r8 ? 0 : -1))
            if (r3 >= 0) goto L9f
            goto L46
        L9f:
            int r3 = (int) r8     // Catch: java.lang.Throwable -> L20
            r1.k(r3)     // Catch: java.lang.Throwable -> L20
            goto L6
        La5:
            r1.j(r2)
            return r4
        La9:
            r1.j(r2)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC1972di.L(com.google.android.gms.internal.ads.Kn, int, int, boolean):boolean");
    }

    /* JADX WARN: Finally extract failed */
    /* JADX WARN: Removed duplicated region for block: B:154:0x026c  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x027b  */
    /* JADX WARN: Removed duplicated region for block: B:168:0x0298 A[Catch: all -> 0x0136, Exception -> 0x0256, OutOfMemoryError -> 0x025b, TRY_ENTER, TRY_LEAVE, TryCatch #2 {all -> 0x0136, blocks: (B:83:0x0105, B:93:0x013f, B:96:0x0146, B:107:0x0170, B:110:0x01a2, B:118:0x01cd, B:120:0x01e1, B:122:0x01e8, B:121:0x01e4, B:136:0x0207, B:138:0x021e, B:140:0x0245, B:142:0x024c, B:141:0x0248, B:165:0x0285, B:168:0x0298, B:170:0x02a1, B:181:0x02e4, B:183:0x0301, B:185:0x0308, B:184:0x0304, B:178:0x02c4, B:180:0x02e0, B:197:0x0326, B:203:0x0367, B:207:0x03a1, B:211:0x03ae, B:212:0x03b4, B:214:0x03ba, B:216:0x03c1, B:217:0x03c5, B:225:0x03e6, B:229:0x0411, B:231:0x041c, B:232:0x044e, B:233:0x0459, B:235:0x045f, B:237:0x0466, B:238:0x046a, B:243:0x0483, B:250:0x0494, B:252:0x04be, B:253:0x04cd, B:254:0x04d8), top: B:266:0x00f2 }] */
    /* JADX WARN: Removed duplicated region for block: B:178:0x02c4 A[Catch: all -> 0x0136, Exception -> 0x02be, OutOfMemoryError -> 0x02c1, TryCatch #2 {all -> 0x0136, blocks: (B:83:0x0105, B:93:0x013f, B:96:0x0146, B:107:0x0170, B:110:0x01a2, B:118:0x01cd, B:120:0x01e1, B:122:0x01e8, B:121:0x01e4, B:136:0x0207, B:138:0x021e, B:140:0x0245, B:142:0x024c, B:141:0x0248, B:165:0x0285, B:168:0x0298, B:170:0x02a1, B:181:0x02e4, B:183:0x0301, B:185:0x0308, B:184:0x0304, B:178:0x02c4, B:180:0x02e0, B:197:0x0326, B:203:0x0367, B:207:0x03a1, B:211:0x03ae, B:212:0x03b4, B:214:0x03ba, B:216:0x03c1, B:217:0x03c5, B:225:0x03e6, B:229:0x0411, B:231:0x041c, B:232:0x044e, B:233:0x0459, B:235:0x045f, B:237:0x0466, B:238:0x046a, B:243:0x0483, B:250:0x0494, B:252:0x04be, B:253:0x04cd, B:254:0x04d8), top: B:266:0x00f2 }] */
    /* JADX WARN: Removed duplicated region for block: B:183:0x0301 A[Catch: all -> 0x0136, Exception -> 0x02be, OutOfMemoryError -> 0x02c1, TryCatch #2 {all -> 0x0136, blocks: (B:83:0x0105, B:93:0x013f, B:96:0x0146, B:107:0x0170, B:110:0x01a2, B:118:0x01cd, B:120:0x01e1, B:122:0x01e8, B:121:0x01e4, B:136:0x0207, B:138:0x021e, B:140:0x0245, B:142:0x024c, B:141:0x0248, B:165:0x0285, B:168:0x0298, B:170:0x02a1, B:181:0x02e4, B:183:0x0301, B:185:0x0308, B:184:0x0304, B:178:0x02c4, B:180:0x02e0, B:197:0x0326, B:203:0x0367, B:207:0x03a1, B:211:0x03ae, B:212:0x03b4, B:214:0x03ba, B:216:0x03c1, B:217:0x03c5, B:225:0x03e6, B:229:0x0411, B:231:0x041c, B:232:0x044e, B:233:0x0459, B:235:0x045f, B:237:0x0466, B:238:0x046a, B:243:0x0483, B:250:0x0494, B:252:0x04be, B:253:0x04cd, B:254:0x04d8), top: B:266:0x00f2 }] */
    /* JADX WARN: Removed duplicated region for block: B:184:0x0304 A[Catch: all -> 0x0136, Exception -> 0x02be, OutOfMemoryError -> 0x02c1, TryCatch #2 {all -> 0x0136, blocks: (B:83:0x0105, B:93:0x013f, B:96:0x0146, B:107:0x0170, B:110:0x01a2, B:118:0x01cd, B:120:0x01e1, B:122:0x01e8, B:121:0x01e4, B:136:0x0207, B:138:0x021e, B:140:0x0245, B:142:0x024c, B:141:0x0248, B:165:0x0285, B:168:0x0298, B:170:0x02a1, B:181:0x02e4, B:183:0x0301, B:185:0x0308, B:184:0x0304, B:178:0x02c4, B:180:0x02e0, B:197:0x0326, B:203:0x0367, B:207:0x03a1, B:211:0x03ae, B:212:0x03b4, B:214:0x03ba, B:216:0x03c1, B:217:0x03c5, B:225:0x03e6, B:229:0x0411, B:231:0x041c, B:232:0x044e, B:233:0x0459, B:235:0x045f, B:237:0x0466, B:238:0x046a, B:243:0x0483, B:250:0x0494, B:252:0x04be, B:253:0x04cd, B:254:0x04d8), top: B:266:0x00f2 }] */
    /* JADX WARN: Removed duplicated region for block: B:198:0x035d  */
    /* JADX WARN: Removed duplicated region for block: B:219:0x03da  */
    /* JADX WARN: Removed duplicated region for block: B:244:0x0488  */
    /* JADX WARN: Removed duplicated region for block: B:260:0x04f7  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.W0 M(int r33, com.google.android.gms.internal.ads.Kn r34, boolean r35, com.google.android.gms.internal.ads.C1 r36) {
        /*
            Method dump skipped, instructions count: 1322
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC1972di.M(int, com.google.android.gms.internal.ads.Kn, boolean, com.google.android.gms.internal.ads.C1):com.google.android.gms.internal.ads.W0");
    }

    public static zze a(Throwable th) {
        if (th instanceof zzedj) {
            zzedj zzedjVar = (zzedj) th;
            return t(zzedjVar.a, zzedjVar.b);
        }
        if (th instanceof zzdwf) {
            return th.getMessage() == null ? x(((zzdwf) th).a, null, null) : x(((zzdwf) th).a, th.getMessage(), null);
        }
        if (!(th instanceof com.google.android.gms.ads.internal.util.zzba)) {
            return x(1, null, null);
        }
        com.google.android.gms.ads.internal.util.zzba zzbaVar = (com.google.android.gms.ads.internal.util.zzba) th;
        int i2 = zzbaVar.a;
        String message = zzbaVar.getMessage();
        if (message == null) {
            message = "";
        }
        return new zze(i2, message, "com.google.android.gms.ads", null, null);
    }

    public static String b(ArrayList arrayList) {
        Iterator it2 = arrayList.iterator();
        String str = null;
        boolean z2 = false;
        while (it2.hasNext()) {
            String str2 = ((L1) it2.next()).a.g.m;
            if (AbstractC2514q5.j(str2)) {
                return "video/mp4";
            }
            if (AbstractC2514q5.h(str2)) {
                z2 = true;
            } else if (AbstractC2514q5.i(str2)) {
                if (Objects.equals(str2, "image/heic")) {
                    str = "image/heif";
                } else if (Objects.equals(str2, "image/avif")) {
                    str = "image/avif";
                }
            }
        }
        return z2 ? "audio/mp4" : str != null ? str : "application/mp4";
    }

    public static HashMap c(String str) {
        try {
            if (TextUtils.isEmpty(str)) {
                return null;
            }
            return (HashMap) new ObjectInputStream(new ByteArrayInputStream(Base64.decode(str.getBytes(), 0))).readObject();
        } catch (IOException | ClassNotFoundException unused) {
            return null;
        }
    }

    public static synchronized Executor d() {
        try {
            if (b == null) {
                String str = Yo.a;
                b = Executors.newSingleThreadExecutor(new ThreadFactoryC1733Mc("ExoPlayer:BackgroundExecutor"));
            }
        } catch (Throwable th) {
            throw th;
        }
        return b;
    }

    public static void e(MediaFormat mediaFormat, String str, int i2) {
        if (i2 != -1) {
            mediaFormat.setInteger(str, i2);
        }
    }

    public static void f(com.google.common.util.concurrent.e eVar, String str) {
        C2332lw c2332lw = new C2332lw(str, 4);
        eVar.a(new Qv(0, eVar, c2332lw), AbstractC2270kd.g);
    }

    public static void g(String str, boolean z2) throws zzdn {
        if (!z2) {
            throw new zzdn(str);
        }
    }

    public static void h(AtomicReference atomicReference, C2147hi c2147hi) {
        Object obj = atomicReference.get();
        if (obj == null) {
            return;
        }
        try {
            c2147hi.mo16b(obj);
        } catch (RemoteException e2) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
        } catch (NullPointerException e3) {
            com.google.android.gms.ads.internal.util.client.i.i("NullPointerException occurs when invoking a method from a delegating listener.", e3);
        }
    }

    public static boolean i(Context context) {
        DisplayManager displayManager = (DisplayManager) context.getSystemService("display");
        Display display = displayManager != null ? displayManager.getDisplay(0) : null;
        if (display != null && display.isHdr()) {
            for (int i2 : display.getHdrCapabilities().getSupportedHdrTypes()) {
                if (i2 == 1) {
                    return true;
                }
            }
        }
        return false;
    }

    public static int j(int i2) {
        return (i2 == 0 || i2 == 3) ? 1 : 2;
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0091  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.bumptech.glide.load.engine.cache.f k(com.google.android.gms.internal.ads.C2466p0 r10) {
        /*
            r0 = 16
            int r1 = r10.f(r0)
            int r0 = r10.f(r0)
            r2 = 65535(0xffff, float:9.1834E-41)
            r3 = 4
            if (r0 != r2) goto L18
            r0 = 24
            int r0 = r10.f(r0)
            r2 = 7
            goto L19
        L18:
            r2 = r3
        L19:
            int r0 = r0 + r2
            r2 = 44097(0xac41, float:6.1793E-41)
            if (r1 != r2) goto L21
            int r0 = r0 + 2
        L21:
            r1 = 2
            int r2 = r10.f(r1)
            r4 = 3
            if (r2 != r4) goto L32
        L29:
            r10.f(r1)
            boolean r2 = r10.w()
            if (r2 != 0) goto L29
        L32:
            r2 = 10
            int r2 = r10.f(r2)
            boolean r5 = r10.w()
            if (r5 == 0) goto L47
            int r5 = r10.f(r4)
            if (r5 <= 0) goto L47
            r10.u(r1)
        L47:
            boolean r5 = r10.w()
            r6 = 1
            r7 = 48000(0xbb80, float:6.7262E-41)
            r8 = 44100(0xac44, float:6.1797E-41)
            if (r6 == r5) goto L56
            r5 = r8
            goto L57
        L56:
            r5 = r7
        L57:
            int r10 = r10.f(r3)
            int[] r9 = com.google.android.gms.internal.ads.AbstractC1972di.c
            if (r5 != r8) goto L66
            r8 = 13
            if (r10 != r8) goto L66
            r10 = r9[r8]
            goto L94
        L66:
            r8 = 0
            if (r5 != r7) goto L93
            r7 = 14
            if (r10 >= r7) goto L93
            r7 = r9[r10]
            int r2 = r2 % 5
            r8 = 8
            if (r2 == r6) goto L8c
            r6 = 11
            if (r2 == r1) goto L87
            if (r2 == r4) goto L8c
            if (r2 == r3) goto L7e
            goto L91
        L7e:
            if (r10 == r4) goto L84
            if (r10 == r8) goto L84
            if (r10 != r6) goto L91
        L84:
            int r10 = r7 + 1
            goto L94
        L87:
            if (r10 == r8) goto L84
            if (r10 != r6) goto L91
            goto L84
        L8c:
            if (r10 == r4) goto L84
            if (r10 != r8) goto L91
            goto L84
        L91:
            r10 = r7
            goto L94
        L93:
            r10 = r8
        L94:
            com.bumptech.glide.load.engine.cache.f r1 = new com.bumptech.glide.load.engine.cache.f
            r2 = 0
            r1.<init>(r2, r5, r0, r10)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC1972di.k(com.google.android.gms.internal.ads.p0):com.bumptech.glide.load.engine.cache.f");
    }

    public static zze l(Throwable th, C2923zm c2923zm) {
        zze zzeVar;
        zze zzeVarA = a(th);
        int i2 = zzeVarA.a;
        if ((i2 == 3 || i2 == 0) && (zzeVar = zzeVarA.d) != null && !zzeVar.c.equals("com.google.android.gms.ads")) {
            zzeVarA.d = null;
        }
        if (c2923zm != null) {
            zzeVarA.e = new Ug(c2923zm.e, "", c2923zm, c2923zm.d, c2923zm.c);
        }
        return zzeVarA;
    }

    public static Fi m(Kn kn) {
        kn.k(1);
        int iB = kn.B();
        long j2 = kn.b;
        long j3 = iB;
        int i2 = iB / 18;
        long[] jArrCopyOf = new long[i2];
        long[] jArrCopyOf2 = new long[i2];
        int i3 = 0;
        while (true) {
            if (i3 >= i2) {
                break;
            }
            long jG = kn.G();
            if (jG == -1) {
                jArrCopyOf = Arrays.copyOf(jArrCopyOf, i3);
                jArrCopyOf2 = Arrays.copyOf(jArrCopyOf2, i3);
                break;
            }
            jArrCopyOf[i3] = jG;
            jArrCopyOf2[i3] = kn.G();
            kn.k(2);
            i3++;
        }
        kn.k((int) ((j2 + j3) - kn.b));
        return new Fi(2, jArrCopyOf, jArrCopyOf2);
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x002d A[Catch: all -> 0x0021, TryCatch #0 {all -> 0x0021, blocks: (B:4:0x0003, B:6:0x0007, B:7:0x000e, B:9:0x0012, B:11:0x0018, B:17:0x0025, B:20:0x003a, B:19:0x002d), top: B:24:0x0003 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void o(android.content.Context r2, boolean r3) {
        /*
            java.lang.Object r0 = com.google.android.gms.internal.ads.AbstractC1972di.K
            monitor-enter(r0)
            com.google.android.gms.internal.appset.g r1 = com.google.android.gms.internal.ads.AbstractC1972di.J     // Catch: java.lang.Throwable -> L21
            if (r1 != 0) goto Le
            com.google.android.gms.internal.appset.g r1 = new com.google.android.gms.internal.appset.g     // Catch: java.lang.Throwable -> L21
            r1.<init>(r2)     // Catch: java.lang.Throwable -> L21
            com.google.android.gms.internal.ads.AbstractC1972di.J = r1     // Catch: java.lang.Throwable -> L21
        Le:
            com.google.android.gms.tasks.Task r2 = com.google.android.gms.internal.ads.AbstractC1972di.I     // Catch: java.lang.Throwable -> L21
            if (r2 == 0) goto L2d
            boolean r2 = r2.k()     // Catch: java.lang.Throwable -> L21
            if (r2 == 0) goto L23
            com.google.android.gms.tasks.Task r2 = com.google.android.gms.internal.ads.AbstractC1972di.I     // Catch: java.lang.Throwable -> L21
            boolean r2 = r2.l()     // Catch: java.lang.Throwable -> L21
            if (r2 == 0) goto L2d
            goto L23
        L21:
            r2 = move-exception
            goto L3c
        L23:
            if (r3 == 0) goto L3a
            com.google.android.gms.tasks.Task r2 = com.google.android.gms.internal.ads.AbstractC1972di.I     // Catch: java.lang.Throwable -> L21
            boolean r2 = r2.k()     // Catch: java.lang.Throwable -> L21
            if (r2 == 0) goto L3a
        L2d:
            com.google.android.gms.internal.appset.g r2 = com.google.android.gms.internal.ads.AbstractC1972di.J     // Catch: java.lang.Throwable -> L21
            java.lang.String r3 = "the appSetIdClient shouldn't be null"
            com.google.android.gms.common.internal.u.i(r2, r3)     // Catch: java.lang.Throwable -> L21
            com.google.android.gms.tasks.Task r2 = r2.b()     // Catch: java.lang.Throwable -> L21
            com.google.android.gms.internal.ads.AbstractC1972di.I = r2     // Catch: java.lang.Throwable -> L21
        L3a:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L21
            return
        L3c:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L21
            throw r2
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC1972di.o(android.content.Context, boolean):void");
    }

    public static void p(MediaFormat mediaFormat, List list) {
        for (int i2 = 0; i2 < list.size(); i2++) {
            mediaFormat.setByteBuffer(android.support.v4.media.session.a.f(i2, "csd-"), ByteBuffer.wrap((byte[]) list.get(i2)));
        }
    }

    public static void q(S9 s9, JSONObject jSONObject) {
        StringBuilder sbY = android.support.v4.media.session.a.y("(window.AFMA_ReceiveMessage || function() {})('openIntentAsync',", jSONObject.toString(), ");");
        com.google.android.gms.ads.internal.util.client.i.d("Dispatching AFMA event: ".concat(sbY.toString()));
        s9.zza(sbY.toString());
    }

    public static int r(int i2, byte[] bArr, int i3) {
        int iW = w(i2, bArr);
        if (i3 == 0 || i3 == 3) {
            return iW;
        }
        while (true) {
            int length = bArr.length;
            if (iW >= length - 1) {
                return length;
            }
            int i4 = iW + 1;
            if ((iW - i2) % 2 == 0 && bArr[i4] == 0) {
                return iW;
            }
            iW = w(i4, bArr);
        }
    }

    public static int s(C2466p0 c2466p0, int i2, int i3, int i4) {
        AbstractC1795We.B(Math.max(Math.max(i2, i3), i4) <= 31);
        int i5 = (1 << i2) - 1;
        int i6 = (1 << i3) - 1;
        AbstractC2025es.e(AbstractC2025es.e(i5, i6), 1 << i4);
        if (c2466p0.a() >= i2) {
            int iF = c2466p0.f(i2);
            if (iF == i5) {
                if (c2466p0.a() >= i3) {
                    int iF2 = c2466p0.f(i3);
                    iF += iF2;
                    if (iF2 == i6) {
                        if (c2466p0.a() >= i4) {
                            return c2466p0.f(i4) + iF;
                        }
                    }
                }
            }
            return iF;
        }
        return -1;
    }

    public static zze t(int i2, zze zzeVar) {
        if (i2 == 0) {
            throw null;
        }
        if (i2 == 8) {
            if (((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.m8)).intValue() > 0) {
                return zzeVar;
            }
            i2 = 8;
        }
        return x(i2, null, zzeVar);
    }

    public static void u(int i2, Kn kn) {
        kn.g(7);
        byte[] bArr = kn.a;
        bArr[0] = -84;
        bArr[1] = 64;
        bArr[2] = -1;
        bArr[3] = -1;
        bArr[4] = (byte) ((i2 >> 16) & 255);
        bArr[5] = (byte) ((i2 >> 8) & 255);
        bArr[6] = (byte) (i2 & 255);
    }

    public static void v(ArrayList arrayList, I3 i3) {
        String str = (String) i3.o();
        if (TextUtils.isEmpty(str)) {
            return;
        }
        arrayList.add(str);
    }

    public static int w(int i2, byte[] bArr) {
        while (true) {
            int length = bArr.length;
            if (i2 >= length) {
                return length;
            }
            if (bArr[i2] == 0) {
                return i2;
            }
            i2++;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    public static zze x(int i2, String str, zze zzeVar) {
        String str2;
        int i3 = i2 - 1;
        if (str == null) {
            if (i2 == 0) {
                throw null;
            }
            str = "No fill.";
            switch (i3) {
                case 1:
                    str = "Invalid request.";
                    break;
                case 2:
                    break;
                case 3:
                    str = "App ID missing.";
                    break;
                case 4:
                    str = "Network error.";
                    break;
                case 5:
                    str = "Invalid request: Invalid ad unit ID.";
                    break;
                case 6:
                    str = "Invalid request: Invalid ad size.";
                    break;
                case 7:
                    str = "A mediation adapter failed to show the ad.";
                    break;
                case 8:
                    str = "The ad is not ready.";
                    break;
                case 9:
                    str = "The ad has already been shown.";
                    break;
                case 10:
                    str = "The ad can not be shown when app is not in foreground.";
                    break;
                case 11:
                default:
                    str = "Internal error.";
                    break;
                case 12:
                    if (((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.p8)).intValue() <= 0) {
                        str = "The mediation adapter did not return an ad.";
                        break;
                    }
                    break;
                case 13:
                    str = "Mismatch request IDs.";
                    break;
                case 14:
                    str = "Invalid ad string.";
                    break;
                case 15:
                    str = "Ad inspector had an internal error.";
                    break;
                case 16:
                    str = "Ad inspector failed to load.";
                    break;
                case 17:
                    str = "Ad inspector cannot be opened because the device is not in test mode. See https://developers.google.com/admob/android/test-ads#enable_test_devices for more information.";
                    break;
                case 18:
                    str = "Ad inspector cannot be opened because it is already open.";
                    break;
            }
        }
        String str3 = str;
        if (i2 == 0) {
            throw null;
        }
        int i4 = 0;
        int i5 = 2;
        switch (i3) {
            case 0:
            case 11:
            case 15:
                i5 = i4;
                return new zze(i5, str3, "com.google.android.gms.ads", zzeVar, null);
            case 1:
            case 5:
            case 6:
            case 9:
            case 16:
                i5 = 1;
                return new zze(i5, str3, "com.google.android.gms.ads", zzeVar, null);
            case 2:
            case 10:
            case 18:
                i5 = 3;
                return new zze(i5, str3, "com.google.android.gms.ads", zzeVar, null);
            case 3:
                i4 = 8;
                i5 = i4;
                return new zze(i5, str3, "com.google.android.gms.ads", zzeVar, null);
            case 4:
            case 8:
            case 17:
                return new zze(i5, str3, "com.google.android.gms.ads", zzeVar, null);
            case 7:
                i4 = 4;
                i5 = i4;
                return new zze(i5, str3, "com.google.android.gms.ads", zzeVar, null);
            case 12:
                if (((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.p8)).intValue() <= 0) {
                    i4 = 9;
                    i5 = i4;
                    return new zze(i5, str3, "com.google.android.gms.ads", zzeVar, null);
                }
                i5 = 3;
                return new zze(i5, str3, "com.google.android.gms.ads", zzeVar, null);
            case 13:
                i4 = 10;
                i5 = i4;
                return new zze(i5, str3, "com.google.android.gms.ads", zzeVar, null);
            case 14:
                i4 = 11;
                i5 = i4;
                return new zze(i5, str3, "com.google.android.gms.ads", zzeVar, null);
            default:
                switch (i2) {
                    case 1:
                        str2 = "INTERNAL_ERROR";
                        break;
                    case 2:
                        str2 = "INVALID_REQUEST";
                        break;
                    case 3:
                        str2 = "NO_FILL";
                        break;
                    case 4:
                        str2 = "APP_ID_MISSING";
                        break;
                    case 5:
                        str2 = "NETWORK_ERROR";
                        break;
                    case 6:
                        str2 = "INVALID_AD_UNIT_ID";
                        break;
                    case 7:
                        str2 = "INVALID_AD_SIZE";
                        break;
                    case 8:
                        str2 = "MEDIATION_SHOW_ERROR";
                        break;
                    case 9:
                        str2 = "NOT_READY";
                        break;
                    case 10:
                        str2 = "AD_REUSED";
                        break;
                    case 11:
                        str2 = "APP_NOT_FOREGROUND";
                        break;
                    case 12:
                        str2 = "INTERNAL_SHOW_ERROR";
                        break;
                    case 13:
                        str2 = "MEDIATION_NO_FILL";
                        break;
                    case 14:
                        str2 = "REQUEST_ID_MISMATCH";
                        break;
                    case 15:
                        str2 = "INVALID_AD_STRING";
                        break;
                    case 16:
                        str2 = "AD_INSPECTOR_INTERNAL_ERROR";
                        break;
                    case 17:
                        str2 = "AD_INSPECTOR_FAILED_TO_LOAD";
                        break;
                    case 18:
                        str2 = "AD_INSPECTOR_NOT_IN_TEST_MODE";
                        break;
                    default:
                        str2 = "AD_INSPECTOR_ALREADY_OPEN";
                        break;
                }
                throw new AssertionError("Unknown SdkError: ".concat(str2));
        }
    }

    public static void y(C2466p0 c2466p0) {
        c2466p0.u(3);
        c2466p0.u(8);
        boolean zW = c2466p0.w();
        boolean zW2 = c2466p0.w();
        if (zW) {
            c2466p0.u(5);
        }
        if (zW2) {
            c2466p0.u(6);
        }
    }

    public static void z(C2466p0 c2466p0, G g2) throws zzaz {
        int iF = c2466p0.f(5);
        c2466p0.u(2);
        if (c2466p0.w()) {
            c2466p0.u(5);
        }
        if (iF >= 7 && iF <= 10) {
            c2466p0.t();
        }
        if (c2466p0.w()) {
            int iF2 = c2466p0.f(3);
            if (g2.b == -1 && iF >= 0 && iF <= 15 && (iF2 == 0 || iF2 == 1)) {
                g2.b = iF;
            }
            if (c2466p0.w()) {
                F(c2466p0);
            }
        }
    }

    public abstract HashMap n();

    public String toString() throws IOException {
        switch (this.a) {
            case 21:
                try {
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
                    objectOutputStream.writeObject(n());
                    objectOutputStream.close();
                    return Base64.encodeToString(byteArrayOutputStream.toByteArray(), 0);
                } catch (IOException unused) {
                    return null;
                }
            default:
                return super.toString();
        }
    }
}
