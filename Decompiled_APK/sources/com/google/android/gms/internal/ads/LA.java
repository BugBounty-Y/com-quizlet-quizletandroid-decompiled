package com.google.android.gms.internal.ads;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.os.StrictMode;
import android.text.TextUtils;
import android.util.Log;
import androidx.camera.core.impl.C0186z;
import com.comscore.streaming.ContentType;
import com.google.android.gms.ads.internal.client.zzm;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import com.pubmatic.sdk.video.c;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.ServiceConfigurationError;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class LA {
    public static final int[] a = {1, 2, 2, 2, 2, 3, 3, 4, 4, 5, 6, 6, 6, 7, 8, 8};
    public static final int[] b = {-1, 8000, 16000, 32000, -1, -1, 11025, 22050, 44100, -1, -1, 12000, 24000, 48000, -1, -1};
    public static final int[] c = {64, ContentType.LONG_FORM_ON_DEMAND, 128, 192, 224, 256, 384, 448, com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH, 640, 768, 896, 1024, 1152, 1280, 1536, 1920, 2048, 2304, 2560, 2688, 2816, 2823, 2944, 3072, 3840, 4096, 6144, 7680};
    public static final int[] d = {8000, 16000, 32000, 64000, 128000, 22050, 44100, 88200, 176400, 352800, 12000, 24000, 48000, 96000, 192000, 384000};
    public static final int[] e = {5, 8, 10, 12};
    public static final int[] f = {6, 9, 12, 15};
    public static final int[] g = {2, 4, 6, 8};
    public static final int[] h = {9, 11, 13, 16};
    public static final int[] i = {5, 8, 10, 12};
    public static final int[] j = {1769172845, 1769172786, 1769172787, 1769172788, 1769172789, 1769172790, 1769172793, 1635148593, 1752589105, 1751479857, 1635135537, 1836069937, 1836069938, 862401121, 862401122, 862417462, 862417718, 862414134, 862414646, 1295275552, 1295270176, 1714714144, 1801741417, 1295275600, 1903435808, 1297305174, 1684175153, 1769172332, 1885955686};
    public static final I3 k = new I3("gads:sdk_core_location", 4, "https://googleads.g.doubleclick.net/mads/static/mad/sdk/native/sdk-core-v40-loader.html");
    public static final H5 l = new H5(10);
    public static final H5 m = new H5(14);
    public static final H5 n = new H5(26);
    public static final C2016ej o = new C2016ej(1);
    public static final C2016ej p = new C2016ej(9);
    public static final C2016ej q = new C2016ej(13);
    public static final C2016ej r = new C2016ej(17);
    public static final C2016ej s = new C2016ej(21);
    public static final C2016ej t = new C2016ej(29);
    public static final C2240jq u = new C2240jq(3);
    public static final C2240jq v = new C2240jq(7);
    public static final byte[] w = {0, 0, 0, 1};
    public static final float[] x = {1.0f, 1.0f, 1.0909091f, 0.90909094f, 1.4545455f, 1.2121212f, 2.1818182f, 1.8181819f, 2.909091f, 2.4242425f, 1.6363636f, 1.3636364f, 1.939394f, 1.6161616f, 1.3333334f, 1.5f, 2.0f};
    public static final Object y = new Object();
    public static int[] z = new int[10];

    public static ArrayList A(byte[] bArr) {
        long j2 = ((bArr[11] & 255) << 8) | (bArr[10] & 255);
        ArrayList arrayList = new ArrayList(3);
        arrayList.add(bArr);
        arrayList.add(ByteBuffer.allocate(8).order(ByteOrder.nativeOrder()).putLong((j2 * 1000000000) / 48000).array());
        arrayList.add(ByteBuffer.allocate(8).order(ByteOrder.nativeOrder()).putLong(80000000L).array());
        return arrayList;
    }

    public static int B(C2466p0 c2466p0, int[] iArr) {
        int i2 = 0;
        for (int i3 = 0; i3 < 3 && c2466p0.w(); i3++) {
            i2++;
        }
        int i4 = 0;
        for (int i5 = 0; i5 < i2; i5++) {
            i4 += 1 << iArr[i5];
        }
        return c2466p0.f(iArr[i2]) + i4;
    }

    public static long C(byte b2, byte b3) {
        int i2;
        int i3 = b2 & 255;
        int i4 = b2 & 3;
        if (i4 != 0) {
            i2 = 2;
            if (i4 != 1 && i4 != 2) {
                i2 = b3 & 63;
            }
        } else {
            i2 = 1;
        }
        int i5 = i3 >> 3;
        return i2 * (i5 >= 16 ? 2500 << r6 : i5 >= 12 ? c.a.DEFAULT_MEDIA_URI_TIMEOUT << (i5 & 1) : (i5 & 3) == 3 ? 60000 : c.a.DEFAULT_MEDIA_URI_TIMEOUT << r6);
    }

    public static Cursor D(SQLiteDatabase sQLiteDatabase, int i2) {
        String[] strArr = {"value"};
        String[] strArr2 = new String[1];
        if (i2 == 0) {
            strArr2[0] = "failed_requests";
        } else if (i2 == 1) {
            strArr2[0] = "total_requests";
        } else if (i2 != 2) {
            strArr2[0] = "completed_requests";
        } else {
            strArr2[0] = "last_successful_request_time";
        }
        return sQLiteDatabase.query("offline_signal_statistics", strArr, "statistic_name = ?", strArr2, null, null, null);
    }

    public static C2466p0 E(byte[] bArr) {
        byte b2 = bArr[0];
        if (b2 == Byte.MAX_VALUE || b2 == 100 || b2 == 64 || b2 == 113) {
            return new C2466p0(bArr.length, bArr);
        }
        byte[] bArrCopyOf = Arrays.copyOf(bArr, bArr.length);
        byte b3 = bArrCopyOf[0];
        if (b3 == -2 || b3 == -1 || b3 == 37 || b3 == -14 || b3 == -24) {
            for (int i2 = 0; i2 < bArrCopyOf.length - 1; i2 += 2) {
                byte b4 = bArrCopyOf[i2];
                int i3 = i2 + 1;
                bArrCopyOf[i2] = bArrCopyOf[i3];
                bArrCopyOf[i3] = b4;
            }
        }
        int length = bArrCopyOf.length;
        C2466p0 c2466p0 = new C2466p0(length, bArrCopyOf);
        if (bArrCopyOf[0] == 31) {
            C2466p0 c2466p02 = new C2466p0(length, bArrCopyOf);
            while (c2466p02.a() >= 16) {
                c2466p02.u(2);
                int iF = c2466p02.f(14);
                int iMin = Math.min(8 - c2466p0.d, 14);
                int i4 = c2466p0.d;
                int i5 = (8 - i4) - iMin;
                byte[] bArr2 = c2466p0.b;
                int i6 = c2466p0.c;
                byte b5 = (byte) (((65280 >> i4) | ((1 << i5) - 1)) & bArr2[i6]);
                bArr2[i6] = b5;
                int i7 = 14 - iMin;
                int i8 = iF & 16383;
                bArr2[i6] = (byte) (b5 | ((i8 >>> i7) << i5));
                int i9 = i6 + 1;
                while (i7 > 8) {
                    i7 -= 8;
                    c2466p0.b[i9] = (byte) (i8 >>> i7);
                    i9++;
                }
                byte[] bArr3 = c2466p0.b;
                byte b6 = (byte) (bArr3[i9] & ((1 << r7) - 1));
                bArr3[i9] = b6;
                bArr3[i9] = (byte) (((i8 & ((1 << i7) - 1)) << (8 - i7)) | b6);
                c2466p0.u(14);
                c2466p0.x();
            }
        }
        int length2 = bArrCopyOf.length;
        c2466p0.b = bArrCopyOf;
        c2466p0.c = 0;
        c2466p0.d = 0;
        c2466p0.e = length2;
        return c2466p0;
    }

    /* JADX WARN: Removed duplicated region for block: B:106:0x019d  */
    /* JADX WARN: Removed duplicated region for block: B:109:0x01a6  */
    /* JADX WARN: Removed duplicated region for block: B:117:0x01d6  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x01ea  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x01f5  */
    /* JADX WARN: Removed duplicated region for block: B:129:0x01fe  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0203 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:132:0x0205  */
    /* JADX WARN: Removed duplicated region for block: B:135:0x0211  */
    /* JADX WARN: Removed duplicated region for block: B:137:0x022e  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0161  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x0183  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.Js F(int r24, byte[] r25, int r26) {
        /*
            Method dump skipped, instructions count: 574
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.LA.F(int, byte[], int):com.google.android.gms.internal.ads.Js");
    }

    public static String G(List list) {
        for (int i2 = 0; i2 < list.size(); i2++) {
            byte[] bArr = (byte[]) list.get(i2);
            int length = bArr.length;
            if (length > 3) {
                boolean[] zArr = new boolean[3];
                C2244ju c2244ju = AbstractC2330lu.b;
                AbstractC2543qs.g(4, "initialCapacity");
                Object[] objArrCopyOf = new Object[4];
                int i3 = 0;
                int i4 = 0;
                while (true) {
                    int length2 = bArr.length;
                    if (i3 >= length2) {
                        break;
                    }
                    int iC = c(bArr, i3, length2, zArr);
                    if (iC != length2) {
                        Integer numValueOf = Integer.valueOf(iC);
                        int length3 = objArrCopyOf.length;
                        int i5 = i4 + 1;
                        int iH = AbstractC2027eu.h(length3, i5);
                        if (iH > length3) {
                            objArrCopyOf = Arrays.copyOf(objArrCopyOf, iH);
                        }
                        objArrCopyOf[i4] = numValueOf;
                        i4 = i5;
                    }
                    i3 = iC + 3;
                }
                Bu buM = AbstractC2330lu.m(i4, objArrCopyOf);
                for (int i6 = 0; i6 < buM.d; i6++) {
                    if (((Integer) buM.get(i6)).intValue() + 3 < length) {
                        C2466p0 c2466p0 = new C2466p0(((Integer) buM.get(i6)).intValue() + 3, bArr, length);
                        com.bumptech.glide.load.engine.cache.f fVarL = L(c2466p0);
                        if (fVarL.a == 33 && fVarL.b == 0) {
                            c2466p0.k(4);
                            int iB = c2466p0.b(3);
                            c2466p0.i();
                            Oq oqM = M(c2466p0, true, iB, null);
                            return Hi.c(oqM.a, oqM.b, oqM.c, oqM.d, oqM.e, oqM.f);
                        }
                    }
                }
            }
        }
        return null;
    }

    public static void H(SQLiteDatabase sQLiteDatabase, String str) {
        ContentValues contentValues = new ContentValues();
        contentValues.put("statistic_name", str);
        contentValues.put("value", (Integer) 0);
        sQLiteDatabase.insert("offline_signal_statistics", null, contentValues);
    }

    public static void I(SQLiteDatabase sQLiteDatabase, String str) {
        ContentValues contentValues = new ContentValues();
        contentValues.put("value", (Integer) 0);
        sQLiteDatabase.update("offline_signal_statistics", contentValues, "statistic_name = ?", new String[]{str});
    }

    public static void J(boolean[] zArr) {
        zArr[0] = false;
        zArr[1] = false;
        zArr[2] = false;
    }

    public static boolean K(byte[] bArr, int i2, C1832aG c1832aG) {
        int i3;
        String str = c1832aG.m;
        if (Objects.equals(str, "video/avc")) {
            byte b2 = bArr[4];
            if (((b2 & 96) >> 5) == 0 && ((i3 = b2 & 31) == 1 || i3 == 9 || i3 == 14)) {
                return false;
            }
        } else if (Objects.equals(str, "video/hevc")) {
            com.bumptech.glide.load.engine.cache.f fVarL = L(new C2466p0(4, bArr, i2 + 4));
            int i4 = fVarL.a;
            if (i4 == 35) {
                return false;
            }
            if (i4 <= 14 && i4 % 2 == 0) {
                if (fVarL.c == c1832aG.B - 1) {
                    return false;
                }
            }
        }
        return true;
    }

    public static com.bumptech.glide.load.engine.cache.f L(C2466p0 c2466p0) {
        c2466p0.i();
        return new com.bumptech.glide.load.engine.cache.f(false, c2466p0.b(6), c2466p0.b(6), c2466p0.b(3) - 1);
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0074  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.Oq M(com.google.android.gms.internal.ads.C2466p0 r18, boolean r19, int r20, com.google.android.gms.internal.ads.Oq r21) {
        /*
            r0 = r18
            r1 = r20
            r2 = r21
            r3 = 6
            int[] r4 = new int[r3]
            r5 = 8
            r6 = 0
            if (r19 == 0) goto L41
            r2 = 2
            int r2 = r0.b(r2)
            boolean r7 = r0.n()
            r8 = 5
            int r8 = r0.b(r8)
            r9 = r6
            r10 = r9
        L1e:
            r11 = 32
            if (r9 >= r11) goto L2e
            boolean r11 = r0.n()
            if (r11 == 0) goto L2b
            r11 = 1
            int r11 = r11 << r9
            r10 = r10 | r11
        L2b:
            int r9 = r9 + 1
            goto L1e
        L2e:
            r9 = r6
        L2f:
            if (r9 >= r3) goto L3a
            int r11 = r0.b(r5)
            r4[r9] = r11
            int r9 = r9 + 1
            goto L2f
        L3a:
            r12 = r2
        L3b:
            r16 = r4
            r13 = r7
            r14 = r8
            r15 = r10
            goto L55
        L41:
            if (r2 == 0) goto L4f
            int r3 = r2.a
            boolean r7 = r2.b
            int r8 = r2.c
            int r10 = r2.d
            int[] r4 = r2.e
            r12 = r3
            goto L3b
        L4f:
            r16 = r4
            r12 = r6
            r13 = r12
            r14 = r13
            r15 = r14
        L55:
            int r17 = r0.b(r5)
            r2 = r6
        L5a:
            if (r6 >= r1) goto L6f
            boolean r3 = r0.n()
            if (r3 == 0) goto L64
            int r2 = r2 + 88
        L64:
            boolean r3 = r0.n()
            if (r3 == 0) goto L6c
            int r2 = r2 + 8
        L6c:
            int r6 = r6 + 1
            goto L5a
        L6f:
            r0.k(r2)
            if (r1 <= 0) goto L79
            int r5 = r5 - r1
            int r5 = r5 + r5
            r0.k(r5)
        L79:
            com.google.android.gms.internal.ads.Oq r11 = new com.google.android.gms.internal.ads.Oq
            r11.<init>(r12, r13, r14, r15, r16, r17)
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.LA.M(com.google.android.gms.internal.ads.p0, boolean, int, com.google.android.gms.internal.ads.Oq):com.google.android.gms.internal.ads.Oq");
    }

    public static void N(C2466p0 c2466p0) {
        int iO = c2466p0.o() + 1;
        c2466p0.k(8);
        for (int i2 = 0; i2 < iO; i2++) {
            c2466p0.o();
            c2466p0.o();
            c2466p0.i();
        }
        c2466p0.k(20);
    }

    public static int a(SQLiteDatabase sQLiteDatabase, int i2) {
        int i3 = 0;
        if (i2 == 2) {
            return 0;
        }
        Cursor cursorD = D(sQLiteDatabase, i2);
        if (cursorD.getCount() > 0) {
            cursorD.moveToNext();
            i3 = cursorD.getInt(cursorD.getColumnIndexOrThrow("value"));
        }
        cursorD.close();
        return i3;
    }

    public static int b(String str) throws UnsupportedEncodingException {
        byte[] bytes;
        int i2;
        try {
            bytes = str.getBytes("UTF-8");
        } catch (UnsupportedEncodingException unused) {
            bytes = str.getBytes();
        }
        int length = bytes.length;
        int i3 = 0;
        int i4 = 0;
        while (true) {
            i2 = length & (-4);
            if (i3 >= i2) {
                break;
            }
            int i5 = ((bytes[i3] & 255) | ((bytes[i3 + 1] & 255) << 8) | ((bytes[i3 + 2] & 255) << 16) | (bytes[i3 + 3] << 24)) * (-862048943);
            int i6 = i4 ^ (((i5 >>> 17) | (i5 << 15)) * 461845907);
            i4 = (((i6 >>> 19) | (i6 << 13)) * 5) - 430675100;
            i3 += 4;
        }
        int i7 = length & 3;
        if (i7 == 1) {
            int i8 = ((bytes[i2] & 255) | i) * (-862048943);
            i4 ^= ((i8 >>> 17) | (i8 << 15)) * 461845907;
        } else {
            if (i7 != 2) {
                i = i7 == 3 ? (bytes[i2 + 2] & 255) << 16 : 0;
            }
            i |= (bytes[i2 + 1] & 255) << 8;
            int i82 = ((bytes[i2] & 255) | i) * (-862048943);
            i4 ^= ((i82 >>> 17) | (i82 << 15)) * 461845907;
        }
        int i9 = i4 ^ length;
        int i10 = (i9 ^ (i9 >>> 16)) * (-2048144789);
        int i11 = (i10 ^ (i10 >>> 13)) * (-1028477387);
        return i11 ^ (i11 >>> 16);
    }

    public static int c(byte[] bArr, int i2, int i3, boolean[] zArr) {
        int i4 = i3 - i2;
        AbstractC1795We.L(i4 >= 0);
        if (i4 == 0) {
            return i3;
        }
        if (zArr[0]) {
            J(zArr);
            return i2 - 3;
        }
        if (i4 > 1 && zArr[1] && bArr[i2] == 1) {
            J(zArr);
            return i2 - 2;
        }
        if (i4 > 2 && zArr[2] && bArr[i2] == 0 && bArr[i2 + 1] == 1) {
            J(zArr);
            return i2 - 1;
        }
        int i5 = i3 - 1;
        int i6 = i2 + 2;
        while (i6 < i5) {
            byte b2 = bArr[i6];
            if ((b2 & 254) == 0) {
                int i7 = i6 - 2;
                if (bArr[i7] == 0 && bArr[i6 - 1] == 0 && b2 == 1) {
                    J(zArr);
                    return i7;
                }
                i6 = i7;
            }
            i6 += 3;
        }
        zArr[0] = i4 <= 2 ? !(i4 != 2 ? !(zArr[1] && bArr[i5] == 1) : !(zArr[2] && bArr[i3 + (-2)] == 0 && bArr[i5] == 1)) : bArr[i3 + (-3)] == 0 && bArr[i3 + (-2)] == 0 && bArr[i5] == 1;
        zArr[1] = i4 <= 1 ? zArr[2] && bArr[i5] == 0 : bArr[i3 + (-2)] == 0 && bArr[i5] == 0;
        zArr[2] = bArr[i5] == 0;
        return i3;
    }

    public static long d(String str) {
        try {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
            simpleDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
            return simpleDateFormat.parse(str).getTime();
        } catch (ParseException e2) {
            if ("0".equals(str) || "-1".equals(str)) {
                H3.b("Unable to parse dateStr: %s, falling back to 0", str);
                return 0L;
            }
            Log.e("Volley", H3.c("Unable to parse dateStr: %s, falling back to 0", str), e2);
            return 0L;
        }
    }

    public static com.google.android.gms.ads.internal.client.zzr e(Context context, List list) {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            Wp wp = (Wp) it2.next();
            if (wp.c) {
                arrayList.add(com.google.android.gms.ads.h.p);
            } else {
                arrayList.add(new com.google.android.gms.ads.h(wp.a, wp.b));
            }
        }
        return new com.google.android.gms.ads.internal.client.zzr(context, (com.google.android.gms.ads.h[]) arrayList.toArray(new com.google.android.gms.ads.h[arrayList.size()]));
    }

    public static Pq f(Context context, int i2) {
        boolean zBooleanValue;
        if (Uq.a()) {
            int i3 = i2 - 2;
            if (i3 != 20 && i3 != 21) {
                switch (i3) {
                    case 2:
                    case 3:
                    case 6:
                    case 7:
                    case 8:
                        zBooleanValue = ((Boolean) R7.c.o()).booleanValue();
                        break;
                    case 4:
                    case 9:
                    case 10:
                    case 11:
                    case 12:
                    case 13:
                        zBooleanValue = ((Boolean) R7.d.o()).booleanValue();
                        break;
                    case 5:
                        zBooleanValue = ((Boolean) R7.b.o()).booleanValue();
                        break;
                }
            } else {
                zBooleanValue = ((Boolean) R7.e.o()).booleanValue();
            }
            if (zBooleanValue) {
                return new Qq(context, i2);
            }
        }
        return new C2024er();
    }

    public static Object g(Bt bt) {
        StrictMode.ThreadPolicy threadPolicy = StrictMode.getThreadPolicy();
        try {
            StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder(threadPolicy).permitDiskReads().permitDiskWrites().build());
            return bt.zza();
        } finally {
            StrictMode.setThreadPolicy(threadPolicy);
        }
    }

    public static String h(JSONObject jSONObject, String str, String str2) {
        JSONArray jSONArrayOptJSONArray;
        if (jSONObject != null && (jSONArrayOptJSONArray = jSONObject.optJSONArray(str2)) != null) {
            for (int i2 = 0; i2 < jSONArrayOptJSONArray.length(); i2++) {
                JSONObject jSONObjectOptJSONObject = jSONArrayOptJSONArray.optJSONObject(i2);
                if (jSONObjectOptJSONObject != null) {
                    JSONArray jSONArrayOptJSONArray2 = jSONObjectOptJSONObject.optJSONArray("including");
                    JSONArray jSONArrayOptJSONArray3 = jSONObjectOptJSONObject.optJSONArray("excluding");
                    if (s(jSONArrayOptJSONArray2, str) && !s(jSONArrayOptJSONArray3, str)) {
                        return jSONObjectOptJSONObject.optString("effective_ad_unit_id", "");
                    }
                }
            }
        }
        return "";
    }

    public static void i(long j2, Kn kn, InterfaceC2380n0[] interfaceC2380n0Arr) {
        int i2;
        int iU;
        while (true) {
            if (kn.s() <= 1) {
                return;
            }
            int i3 = 0;
            while (true) {
                if (kn.s() == 0) {
                    i2 = -1;
                    break;
                }
                int iZ = kn.z();
                i3 += iZ;
                if (iZ != 255) {
                    i2 = i3;
                    break;
                }
            }
            int i4 = 0;
            while (true) {
                if (kn.s() == 0) {
                    i4 = -1;
                    break;
                }
                int iZ2 = kn.z();
                i4 += iZ2;
                if (iZ2 != 255) {
                    break;
                }
            }
            int i5 = kn.b + i4;
            if (i4 == -1 || i4 > kn.s()) {
                AbstractC2096gb.J("CeaUtil", "Skipping remainder of malformed SEI NAL unit.");
                i5 = kn.c;
            } else if (i2 == 4 && i4 >= 8) {
                int iZ3 = kn.z();
                int iD = kn.D();
                if (iD == 49) {
                    iU = kn.u();
                    iD = 49;
                } else {
                    iU = 0;
                }
                int iZ4 = kn.z();
                if (iD == 47) {
                    kn.k(1);
                    iD = 47;
                }
                boolean z2 = iZ3 == 181 && (iD == 49 || iD == 47) && iZ4 == 3;
                if (iD == 49) {
                    z2 &= iU == 1195456820;
                }
                if (z2) {
                    r(j2, kn, interfaceC2380n0Arr);
                }
            }
            kn.j(i5);
        }
    }

    public static void j(com.google.android.gms.dynamic.a aVar, Throwable th, String str) {
        C1744Ob.a((Context) com.google.android.gms.dynamic.b.I3(aVar)).e(th, str, ((Double) AbstractC2086g8.f.o()).floatValue());
    }

    public static void k(Y1 y1, C0186z c0186z) {
        for (int i2 = 0; i2 < y1.zza(); i2++) {
            long jF = y1.F(i2);
            ArrayList arrayListZzc = y1.zzc(jF);
            if (!arrayListZzc.isEmpty()) {
                if (i2 == y1.zza() - 1) {
                    throw new IllegalStateException();
                }
                long jF2 = y1.F(i2 + 1) - y1.F(i2);
                if (jF2 > 0) {
                    c0186z.mo10b(new X1(arrayListZzc, jF, jF2));
                }
            }
        }
    }

    public static void l(String str, Exception exc) {
        Log.e("OMIDLIB", str, exc);
    }

    public static int m(C1832aG c1832aG) {
        String str = c1832aG.m;
        if (Objects.equals(str, "video/avc")) {
            return 1;
        }
        return (Objects.equals(str, "video/hevc") || AbstractC2514q5.g(c1832aG.j, "video/hevc")) ? 2 : 0;
    }

    public static long n(Kn kn, int i2, int i3) {
        kn.j(i2);
        if (kn.s() < 5) {
            return -9223372036854775807L;
        }
        int iU = kn.u();
        if ((8388608 & iU) != 0 || ((iU >> 8) & 8191) != i3 || (iU & 32) == 0 || kn.z() < 7 || kn.s() < 7 || (kn.z() & 16) != 16) {
            return -9223372036854775807L;
        }
        byte[] bArr = new byte[6];
        kn.f(0, bArr, 6);
        long j2 = bArr[0];
        long j3 = bArr[1];
        long j4 = bArr[2];
        long j5 = bArr[3] & 255;
        return ((j2 & 255) << 25) | ((j3 & 255) << 17) | ((j4 & 255) << 9) | (j5 + j5) | ((bArr[4] & 255) >> 7);
    }

    public static C2683u3 o(A3 a3) throws NumberFormatException {
        long j2;
        boolean z2;
        long j3;
        long j4;
        long j5;
        long jD;
        long j6;
        long j7;
        long jCurrentTimeMillis = System.currentTimeMillis();
        Map map = a3.c;
        if (map == null) {
            return null;
        }
        String str = (String) map.get("Date");
        long jD2 = str != null ? d(str) : 0L;
        String str2 = (String) map.get("Cache-Control");
        int i2 = 0;
        if (str2 != null) {
            String[] strArrSplit = str2.split(",", 0);
            z2 = false;
            j3 = 0;
            j4 = 0;
            while (i2 < strArrSplit.length) {
                String strTrim = strArrSplit[i2].trim();
                if (strTrim.equals("no-cache") || strTrim.equals("no-store")) {
                    return null;
                }
                if (strTrim.startsWith("max-age=")) {
                    try {
                        j4 = Long.parseLong(strTrim.substring(8));
                    } catch (Exception unused) {
                    }
                } else if (strTrim.startsWith("stale-while-revalidate=")) {
                    j3 = Long.parseLong(strTrim.substring(23));
                } else if (strTrim.equals("must-revalidate") || strTrim.equals("proxy-revalidate")) {
                    z2 = true;
                }
                i2++;
            }
            j2 = 0;
            i2 = 1;
        } else {
            j2 = 0;
            z2 = false;
            j3 = 0;
            j4 = 0;
        }
        String str3 = (String) map.get("Expires");
        long jD3 = str3 != null ? d(str3) : j2;
        String str4 = (String) map.get("Last-Modified");
        if (str4 != null) {
            j5 = jCurrentTimeMillis;
            jD = d(str4);
        } else {
            j5 = jCurrentTimeMillis;
            jD = j2;
        }
        String str5 = (String) map.get("ETag");
        if (i2 != 0) {
            long j8 = (j4 * 1000) + j5;
            j7 = z2 ? j8 : (j3 * 1000) + j8;
            j6 = j8;
        } else {
            j6 = (jD2 <= j2 || jD3 < jD2) ? j2 : (jD3 - jD2) + j5;
            j7 = j6;
        }
        C2683u3 c2683u3 = new C2683u3();
        c2683u3.a = a3.b;
        c2683u3.b = str5;
        c2683u3.f = j6;
        c2683u3.e = j7;
        c2683u3.c = jD2;
        c2683u3.d = jD;
        c2683u3.g = map;
        c2683u3.h = a3.d;
        return c2683u3;
    }

    public static Pq p(Context context, int i2, int i3, zzm zzmVar) {
        boolean zMatches;
        Pq pqF = f(context, i2);
        if (pqF instanceof Qq) {
            pqF.zzi();
            pqF.e(i3);
            pqF.d(AbstractC3429b3.c(zzmVar.m));
            String str = zzmVar.p;
            if (TextUtils.isEmpty(str)) {
                zMatches = false;
            } else {
                zMatches = Pattern.matches((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.O8), str);
            }
            if (zMatches) {
                pqF.R(str);
            }
        }
        return pqF;
    }

    public static IA q() {
        String strI;
        ClassLoader classLoader = LA.class.getClassLoader();
        if (IA.class.equals(IA.class)) {
            strI = "com.google.protobuf.BlazeGeneratedExtensionRegistryLiteLoader";
        } else {
            if (!IA.class.getPackage().equals(LA.class.getPackage())) {
                throw new IllegalArgumentException(IA.class.getName());
            }
            strI = androidx.compose.ui.node.B.i(IA.class.getPackage().getName(), ".BlazeGenerated", IA.class.getSimpleName(), "Loader");
        }
        try {
            try {
                try {
                    android.support.v4.media.session.a.A(Class.forName(strI, true, classLoader).getConstructor(null).newInstance(null));
                    throw null;
                } catch (InstantiationException e2) {
                    throw new IllegalStateException(e2);
                } catch (InvocationTargetException e3) {
                    throw new IllegalStateException(e3);
                }
            } catch (IllegalAccessException e4) {
                throw new IllegalStateException(e4);
            } catch (NoSuchMethodException e5) {
                throw new IllegalStateException(e5);
            }
        } catch (ClassNotFoundException unused) {
            try {
                Iterator it2 = Arrays.asList(new LA[0]).iterator();
                ArrayList arrayList = new ArrayList();
                while (it2.hasNext()) {
                    try {
                        if (it2.next() == null) {
                            throw null;
                        }
                        throw new ClassCastException();
                    } catch (ServiceConfigurationError e6) {
                        Logger.getLogger(HA.class.getName()).logp(Level.SEVERE, "com.google.protobuf.GeneratedExtensionRegistryLoader", "load", "Unable to load ".concat(IA.class.getSimpleName()), (Throwable) e6);
                    }
                }
                if (arrayList.size() == 1) {
                    return (IA) arrayList.get(0);
                }
                if (arrayList.size() == 0) {
                    return null;
                }
                try {
                    return (IA) IA.class.getMethod("combine", Collection.class).invoke(null, arrayList);
                } catch (IllegalAccessException e7) {
                    throw new IllegalStateException(e7);
                } catch (NoSuchMethodException e8) {
                    throw new IllegalStateException(e8);
                } catch (InvocationTargetException e9) {
                    throw new IllegalStateException(e9);
                }
            } catch (Throwable th) {
                throw new ServiceConfigurationError(th.getMessage(), th);
            }
        }
    }

    public static void r(long j2, Kn kn, InterfaceC2380n0[] interfaceC2380n0Arr) {
        int iZ = kn.z();
        if ((iZ & 64) != 0) {
            int i2 = iZ & 31;
            kn.k(1);
            int i3 = kn.b;
            for (InterfaceC2380n0 interfaceC2380n0 : interfaceC2380n0Arr) {
                int i4 = i2 * 3;
                kn.j(i3);
                interfaceC2380n0.e(i4, kn);
                AbstractC1795We.L(j2 != -9223372036854775807L);
                interfaceC2380n0.f(j2, 1, i4, 0, null);
            }
        }
    }

    public static boolean s(JSONArray jSONArray, String str) {
        if (jSONArray != null && str != null) {
            for (int i2 = 0; i2 < jSONArray.length(); i2++) {
                String strOptString = jSONArray.optString(i2);
                try {
                } catch (PatternSyntaxException e2) {
                    com.google.android.gms.ads.internal.j.C.h.h("RtbAdapterMap.hasAtleastOneRegexMatch", e2);
                }
                if ((((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ua)).booleanValue() ? Pattern.compile(strOptString, 2) : Pattern.compile(strOptString)).matcher(str).lookingAt()) {
                    return true;
                }
            }
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:52:0x00c5  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00f0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String[] t(java.lang.String r11, boolean r12) {
        /*
            Method dump skipped, instructions count: 286
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.LA.t(java.lang.String, boolean):java.lang.String[]");
    }

    public static int u(int i2, byte[] bArr) {
        int i3;
        synchronized (y) {
            int i4 = 0;
            int i5 = 0;
            while (i4 < i2) {
                while (true) {
                    try {
                        if (i4 >= i2 - 2) {
                            i4 = i2;
                            break;
                        }
                        int i6 = i4 + 1;
                        if (bArr[i4] == 0 && bArr[i6] == 0 && bArr[i4 + 2] == 3) {
                            break;
                        }
                        i4 = i6;
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                if (i4 < i2) {
                    int[] iArr = z;
                    int length = iArr.length;
                    if (length <= i5) {
                        z = Arrays.copyOf(iArr, length + length);
                    }
                    z[i5] = i4;
                    i4 += 3;
                    i5++;
                }
            }
            i3 = i2 - i5;
            int i7 = 0;
            int i8 = 0;
            for (int i9 = 0; i9 < i5; i9++) {
                int i10 = z[i9] - i7;
                System.arraycopy(bArr, i7, bArr, i8, i10);
                int i11 = i8 + i10;
                int i12 = i11 + 1;
                bArr[i11] = 0;
                i8 = i11 + 2;
                bArr[i12] = 0;
                i7 += i10 + 3;
            }
            System.arraycopy(bArr, i7, bArr, i8, i3 - i8);
        }
        return i3;
    }

    public static InterfaceC2294l0 v(V v2, boolean z2, boolean z3) {
        InterfaceC2294l0 interfaceC2294l0;
        long j2;
        Kn kn;
        int i2;
        int i3;
        int[] iArr;
        long j3 = v2.j();
        long j4 = -1;
        long j5 = 4096;
        if (j3 != -1 && j3 <= 4096) {
            j5 = j3;
        }
        Kn kn2 = new Kn(64);
        int i4 = (int) j5;
        int i5 = 0;
        int i6 = 0;
        boolean z4 = false;
        while (i6 < i4) {
            kn2.g(8);
            boolean z5 = true;
            if (!v2.k(kn2.a, i5, 8, true)) {
                break;
            }
            long jH = kn2.H();
            int iU = kn2.u();
            if (jH == 1) {
                j2 = j4;
                v2.l(8, kn2.a, 8);
                i2 = 16;
                kn2.i(16);
                jH = kn2.G();
                kn = kn2;
            } else {
                j2 = j4;
                if (jH == 0) {
                    long j6 = v2.j();
                    if (j6 != j2) {
                        jH = (j6 - v2.zze()) + 8;
                    }
                }
                kn = kn2;
                i2 = 8;
            }
            long j7 = jH;
            interfaceC2294l0 = null;
            long j8 = i2;
            if (j7 < j8) {
                return new C1(18);
            }
            i6 += i2;
            if (iU == 1836019574) {
                i4 += (int) j7;
                if (j3 != -1 && i4 > j3) {
                    i4 = (int) j3;
                }
                kn2 = kn;
                j4 = j2;
                i5 = 0;
            } else {
                if (iU == 1836019558 || iU == 1836475768) {
                    i5 = 1;
                    break;
                }
                z4 |= !(iU != 1835295092);
                long j9 = j3;
                if ((i6 + j7) - j8 >= i4) {
                    i5 = 0;
                    break;
                }
                int i7 = (int) (j7 - j8);
                i6 += i7;
                if (iU != 1718909296) {
                    i3 = 0;
                    if (i7 != 0) {
                        v2.e(i7);
                    }
                } else {
                    if (i7 < 8) {
                        return new C1(18);
                    }
                    kn.g(i7);
                    i3 = 0;
                    v2.l(0, kn.a, i7);
                    boolean zY = y(kn.u(), z3) | z4;
                    kn.k(4);
                    int iS = kn.s() / 4;
                    if (!zY && iS > 0) {
                        iArr = new int[iS];
                        int i8 = 0;
                        while (true) {
                            if (i8 >= iS) {
                                z5 = zY;
                                break;
                            }
                            int iU2 = kn.u();
                            iArr[i8] = iU2;
                            if (y(iU2, z3)) {
                                break;
                            }
                            i8++;
                        }
                    } else {
                        z5 = zY;
                        iArr = null;
                    }
                    if (!z5) {
                        C1 c1 = new C1(19);
                        if (iArr != null) {
                            int length = Arrays.copyOf(iArr, iArr.length).length;
                        }
                        return c1;
                    }
                    z4 = z5;
                }
                i5 = i3;
                kn2 = kn;
                j4 = j2;
                j3 = j9;
            }
        }
        interfaceC2294l0 = null;
        return !z4 ? C1.d : z2 != i5 ? i5 != 0 ? C1.b : C1.c : interfaceC2294l0;
    }

    public static void w(SQLiteDatabase sQLiteDatabase, long j2, byte[] bArr) {
        ContentValues contentValues = new ContentValues();
        contentValues.put("timestamp", Long.valueOf(j2));
        contentValues.put("serialized_proto_data", bArr);
        if (sQLiteDatabase.update("offline_signal_contents", contentValues, "timestamp = ?", new String[]{String.valueOf(j2)}) == 0) {
            sQLiteDatabase.insert("offline_signal_contents", null, contentValues);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x004d  */
    /* JADX WARN: Removed duplicated region for block: B:167:0x02e4  */
    /* JADX WARN: Removed duplicated region for block: B:172:0x02ff  */
    /* JADX WARN: Removed duplicated region for block: B:203:0x0393  */
    /* JADX WARN: Removed duplicated region for block: B:211:0x03b7  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0111  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0132  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x014c  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x019e  */
    /* JADX WARN: Removed duplicated region for block: B:99:0x01bc  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.Tr x(byte[] r31, int r32, int r33, com.quizlet.data.repository.classmembership.c r34) {
        /*
            Method dump skipped, instructions count: 967
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.LA.x(byte[], int, int, com.quizlet.data.repository.classmembership.c):com.google.android.gms.internal.ads.Tr");
    }

    public static boolean y(int i2, boolean z2) {
        if ((i2 >>> 8) == 3368816) {
            return true;
        }
        if (i2 == 1751476579) {
            if (z2) {
                return true;
            }
            i2 = 1751476579;
        }
        int[] iArr = j;
        for (int i3 = 0; i3 < 29; i3++) {
            if (iArr[i3] == i2) {
                return true;
            }
        }
        return false;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:57:0x010f  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x013b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.quizlet.data.repository.classmembership.c z(int r41, byte[] r42, int r43) {
        /*
            Method dump skipped, instructions count: 2174
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.LA.z(int, byte[], int):com.quizlet.data.repository.classmembership.c");
    }
}
