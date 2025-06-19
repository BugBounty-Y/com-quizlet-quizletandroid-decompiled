package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.os.SystemClock;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;
import com.comscore.android.ConnectivityType;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3429b3;
import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.EOFException;
import java.io.InterruptedIOException;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;

/* renamed from: com.google.android.gms.internal.ads.gb, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2096gb {
    public static final H5 j;
    public static final C2240jq t;
    public static final int[] a = {96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350};
    public static final int[] b = {0, 1, 2, 3, 4, 5, 6, 8, -1, -1, -1, 7, 8, -1, 8, -1};
    public static final String[] c = {"audio/mpeg-L1", "audio/mpeg-L2", "audio/mpeg"};
    public static final int[] d = {44100, 48000, 32000};
    public static final int[] e = {32000, 64000, 96000, 128000, 160000, 192000, 224000, 256000, 288000, 320000, 352000, 384000, 416000, 448000};
    public static final int[] f = {32000, 48000, 56000, 64000, 80000, 96000, 112000, 128000, 144000, 160000, 176000, 192000, 224000, 256000};
    public static final int[] g = {32000, 48000, 56000, 64000, 80000, 96000, 112000, 128000, 160000, 192000, 224000, 256000, 320000, 384000};
    public static final int[] h = {32000, ConnectivityType.UNKNOWN, 48000, 56000, 64000, 80000, 96000, 112000, 128000, 160000, 192000, 224000, 256000, 320000};
    public static final int[] i = {8000, 16000, 24000, 32000, ConnectivityType.UNKNOWN, 48000, 56000, 64000, 80000, 96000, 112000, 128000, 144000, 160000};
    public static final I3 k = new I3("gads:pan:experiment_id", 4, "");
    public static final H5 l = new H5(11);
    public static final H5 m = new H5(15);
    public static final H5 n = new H5(27);
    public static final C2016ej o = new C2016ej(5);
    public static final C2016ej p = new C2016ej(10);
    public static final C2016ej q = new C2016ej(14);
    public static final Object r = new Object();
    public static final C2016ej s = new C2016ej(22);
    public static final C2240jq u = new C2240jq(4);
    public static final C2240jq v = new C2240jq(8);
    public static final Cw w = new Cw(7);
    public static final C2163hy x = new C2163hy(C2074fx.class, InterfaceC2289kw.class, new Is(28));

    static {
        int i2 = 0;
        j = new H5(i2);
        t = new C2240jq(i2);
    }

    public static void A(String str, String str2, Throwable th) {
        synchronized (r) {
            Log.e(str, g(str2, th));
        }
    }

    public static boolean B(int i2, Kn kn, boolean z) throws zzaz {
        if (kn.s() < 7) {
            if (z) {
                return false;
            }
            throw zzaz.a(null, "too short header: " + kn.s());
        }
        if (kn.z() != i2) {
            if (z) {
                return false;
            }
            throw zzaz.a(null, "expected header type ".concat(String.valueOf(Integer.toHexString(i2))));
        }
        if (kn.z() == 118 && kn.z() == 111 && kn.z() == 114 && kn.z() == 98 && kn.z() == 105 && kn.z() == 115) {
            return true;
        }
        if (z) {
            return false;
        }
        throw zzaz.a(null, "expected characters 'vorbis'");
    }

    public static long C(ByteBuffer byteBuffer) {
        long j2 = byteBuffer.getInt();
        return j2 < 0 ? j2 + 4294967296L : j2;
    }

    public static long D(String[] strArr, int i2) {
        long jB = (LA.b(strArr[0]) + 2147483647L) % 1073807359;
        for (int i3 = 1; i3 < i2; i3++) {
            jB = (((LA.b(strArr[i3]) + 2147483647L) % 1073807359) + ((jB * 16785407) % 1073807359)) % 1073807359;
        }
        return jB;
    }

    public static void E(int i2, Bundle bundle, String str, boolean z) {
        if (z) {
            bundle.putInt(str, i2);
        }
    }

    public static void F(String str, String str2) {
        synchronized (r) {
            Log.i(str, g(str2, null));
        }
    }

    public static int G(C2023eq c2023eq) {
        int iG = AbstractC3429b3.g(c2023eq) - 1;
        return (iG == 0 || iG == 1) ? 7 : 23;
    }

    public static long H(ByteBuffer byteBuffer) {
        long jC = C(byteBuffer) << 32;
        if (jC >= 0) {
            return C(byteBuffer) + jC;
        }
        throw new RuntimeException("I don't know how to deal with UInt64! long is not sufficient and I don't want to use BigInt");
    }

    public static void I(Bundle bundle, String str, String str2, boolean z) {
        if (!z || str2 == null) {
            return;
        }
        bundle.putString(str, str2);
    }

    public static void J(String str, String str2) {
        synchronized (r) {
            Log.w(str, g(str2, null));
        }
    }

    public static void K(Bundle bundle, String str, boolean z, boolean z2) {
        if (z2) {
            bundle.putBoolean(str, z);
        }
    }

    public static void L(com.google.common.util.concurrent.e eVar, Tq tq, Pq pq, boolean z) {
        if (((Boolean) R7.c.o()).booleanValue()) {
            Nv nvT = Nv.t(eVar);
            C3083y1 c3083y1 = new C3083y1(tq, pq, z);
            nvT.a(new Qv(0, nvT, c3083y1), AbstractC2270kd.g);
        }
    }

    public static void M(String str, String str2, Throwable th) {
        synchronized (r) {
            Log.w(str, g(str2, th));
        }
    }

    public static double a(ByteBuffer byteBuffer) {
        byteBuffer.get(new byte[4]);
        return (((((r0[0] << 24) & (-16777216)) | ((r0[1] << 16) & 16711680)) | (65280 & (r0[2] << 8))) | (r0[3] & 255)) / 1.073741824E9d;
    }

    public static int b(int i2) {
        int i3 = 0;
        while (i2 > 0) {
            i2 >>>= 1;
            i3++;
        }
        return i3;
    }

    public static long c(int i2, long j2) {
        if (i2 == 1) {
            return j2;
        }
        int i3 = i2 >> 1;
        long j3 = (j2 * j2) % 1073807359;
        return (i2 & 1) == 0 ? c(i3, j3) % 1073807359 : ((c(i3, j3) % 1073807359) * j2) % 1073807359;
    }

    public static Bundle d(Bundle bundle, String str) {
        Bundle bundle2 = bundle.getBundle(str);
        return bundle2 == null ? new Bundle() : bundle2;
    }

    public static Bundle e(Pair... pairArr) {
        Bundle bundle = new Bundle();
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.h2)).booleanValue()) {
            for (int i2 = 0; i2 < 2; i2++) {
                Pair pair = pairArr[i2];
                if (!TextUtils.isEmpty((CharSequence) pair.first) && ((Long) pair.second).longValue() > 0) {
                    bundle.putLong((String) pair.first, ((Long) pair.second).longValue());
                }
            }
        }
        return bundle;
    }

    public static C2725v2 f(C2725v2 c2725v2, String[] strArr, Map map) {
        int length;
        int i2 = 0;
        if (c2725v2 == null) {
            if (strArr == null) {
                return null;
            }
            int length2 = strArr.length;
            if (length2 == 1) {
                return (C2725v2) map.get(strArr[0]);
            }
            if (length2 > 1) {
                C2725v2 c2725v22 = new C2725v2();
                while (i2 < length2) {
                    c2725v22.d((C2725v2) map.get(strArr[i2]));
                    i2++;
                }
                return c2725v22;
            }
        } else {
            if (strArr != null && strArr.length == 1) {
                c2725v2.d((C2725v2) map.get(strArr[0]));
                return c2725v2;
            }
            if (strArr != null && (length = strArr.length) > 1) {
                while (i2 < length) {
                    c2725v2.d((C2725v2) map.get(strArr[i2]));
                    i2++;
                }
            }
        }
        return c2725v2;
    }

    public static String g(String str, Throwable th) {
        String strReplace;
        if (th != null) {
            synchronized (r) {
                Throwable cause = th;
                while (true) {
                    if (cause == null) {
                        strReplace = Log.getStackTraceString(th).trim().replace("\t", "    ");
                        break;
                    }
                    try {
                        if (cause instanceof UnknownHostException) {
                            strReplace = "UnknownHostException (no network)";
                        } else {
                            cause = cause.getCause();
                        }
                    } finally {
                    }
                }
            }
        } else {
            strReplace = null;
        }
        return !TextUtils.isEmpty(strReplace) ? androidx.compose.ui.node.B.i(str, "\n  ", strReplace.replace("\n", "\n  "), "\n") : str;
    }

    public static void h(B7 b7, C2902z7 c2902z7, String... strArr) {
        if (c2902z7 == null) {
            return;
        }
        com.google.android.gms.ads.internal.j.C.k.getClass();
        b7.c(c2902z7, SystemClock.elapsedRealtime(), strArr);
    }

    public static void i(String str) {
        if (((Boolean) AbstractC2042f8.a.o()).booleanValue()) {
            com.google.android.gms.ads.internal.util.client.i.d(str);
        }
    }

    public static double j(ByteBuffer byteBuffer) {
        byteBuffer.get(new byte[4]);
        return (((((r0[0] << 24) & (-16777216)) | ((r0[1] << 16) & 16711680)) | (65280 & (r0[2] << 8))) | (r0[3] & 255)) / 65536.0d;
    }

    public static int k(int i2) {
        int i3;
        int i4;
        int i5;
        int i6;
        if (!((i2 & (-2097152)) == -2097152) || (i3 = (i2 >>> 19) & 3) == 1 || (i4 = (i2 >>> 17) & 3) == 0 || (i5 = (i2 >>> 12) & 15) == 0 || i5 == 15 || (i6 = (i2 >>> 10) & 3) == 3) {
            return -1;
        }
        int i7 = i5 - 1;
        int i8 = d[i6];
        if (i3 == 2) {
            i8 /= 2;
        } else if (i3 == 0) {
            i8 /= 4;
        }
        int i9 = (i2 >>> 9) & 1;
        if (i4 == 3) {
            return ((((i3 == 3 ? e[i7] : f[i7]) * 12) / i8) + i9) * 4;
        }
        int i10 = i3 == 3 ? i4 == 2 ? g[i7] : h[i7] : i[i7];
        if (i3 == 3) {
            return ((i10 * 144) / i8) + i9;
        }
        return (((i4 == 1 ? 72 : 144) * i10) / i8) + i9;
    }

    /* JADX WARN: Code restructure failed: missing block: B:57:0x00b9, code lost:
    
        if (r11 != 3) goto L64;
     */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0094  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00b3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.F l(com.google.android.gms.internal.ads.C2466p0 r11, boolean r12) throws com.google.android.gms.internal.ads.zzaz {
        /*
            Method dump skipped, instructions count: 266
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC2096gb.l(com.google.android.gms.internal.ads.p0, boolean):com.google.android.gms.internal.ads.F");
    }

    public static K4 m(List list) {
        ArrayList arrayList = new ArrayList();
        for (int i2 = 0; i2 < list.size(); i2++) {
            String str = (String) list.get(i2);
            String str2 = Yo.a;
            String[] strArrSplit = str.split(SimpleComparison.EQUAL_TO_OPERATION, 2);
            if (strArrSplit.length != 2) {
                J("VorbisUtil", "Failed to parse Vorbis comment: ".concat(str));
            } else if (strArrSplit[0].equals("METADATA_BLOCK_PICTURE")) {
                try {
                    arrayList.add(N0.b(new Kn(Base64.decode(strArrSplit[1], 0))));
                } catch (RuntimeException e2) {
                    M("VorbisUtil", "Failed to parse vorbis picture", e2);
                }
            } else {
                arrayList.add(new C2123h1(strArrSplit[0], strArrSplit[1]));
            }
        }
        if (arrayList.isEmpty()) {
            return null;
        }
        return new K4(arrayList);
    }

    public static String n(String[] strArr, int i2, int i3) {
        int i4 = i3 + i2;
        if (strArr.length < i4) {
            com.google.android.gms.ads.internal.util.client.i.e("Unable to construct shingle");
            return "";
        }
        StringBuilder sb = new StringBuilder();
        while (true) {
            int i5 = i4 - 1;
            if (i2 >= i5) {
                sb.append(strArr[i5]);
                return sb.toString();
            }
            sb.append(strArr[i2]);
            sb.append(' ');
            i2++;
        }
    }

    public static void o(SpannableStringBuilder spannableStringBuilder, Object obj, int i2, int i3) {
        for (Object obj2 : spannableStringBuilder.getSpans(i2, i3, obj.getClass())) {
            if (spannableStringBuilder.getSpanStart(obj2) == i2 && spannableStringBuilder.getSpanEnd(obj2) == i3 && spannableStringBuilder.getSpanFlags(obj2) == 33) {
                spannableStringBuilder.removeSpan(obj2);
            }
        }
        spannableStringBuilder.setSpan(obj, i2, i3, 33);
    }

    public static void p(String str) {
        synchronized (r) {
            g(str, null);
        }
    }

    public static void q(String str, boolean z) throws zzaz {
        if (!z) {
            throw zzaz.a(null, str);
        }
    }

    public static C2881yn r(Kn kn, boolean z, boolean z2) throws zzaz {
        if (z) {
            B(3, kn, false);
        }
        kn.b((int) kn.F(), StandardCharsets.UTF_8);
        long jF = kn.F();
        String[] strArr = new String[(int) jF];
        for (int i2 = 0; i2 < jF; i2++) {
            strArr[i2] = kn.b((int) kn.F(), StandardCharsets.UTF_8);
        }
        if (z2 && (kn.z() & 1) == 0) {
            throw zzaz.a(null, "framing bit expected to be set");
        }
        return new C2881yn(strArr, 1);
    }

    public static void s(String str, String str2) {
        synchronized (r) {
            Log.e(str, g(str2, null));
        }
    }

    public static void t(String str, String str2, Bundle bundle) {
        if (str2 != null) {
            bundle.putString(str, str2);
        }
    }

    public static boolean u(P p2) {
        Kn kn = new Kn(8);
        int i2 = C2426o3.a(p2, kn).a;
        if (i2 != 1380533830 && i2 != 1380333108) {
            return false;
        }
        p2.k(kn.a, 0, 4, false);
        kn.j(0);
        int iU = kn.u();
        if (iU == 1463899717) {
            return true;
        }
        s("WavHeaderReader", "Unsupported form type: " + iU);
        return false;
    }

    public static int v(C2466p0 c2466p0) throws zzaz {
        int iF = c2466p0.f(4);
        if (iF == 15) {
            if (c2466p0.a() >= 24) {
                return c2466p0.f(24);
            }
            throw zzaz.a(null, "AAC header insufficient data");
        }
        if (iF < 13) {
            return a[iF];
        }
        throw zzaz.a(null, "AAC header wrong Sampling Frequency Index");
    }

    public static C2426o3 w(int i2, P p2, Kn kn) throws zzaz, EOFException, InterruptedIOException {
        C2426o3 c2426o3A = C2426o3.a(p2, kn);
        while (true) {
            int i3 = c2426o3A.a;
            if (i3 == i2) {
                return c2426o3A;
            }
            AbstractC1642h.s(i3, "Ignoring unknown WAV chunk: ", "WavHeaderReader");
            long j2 = c2426o3A.b;
            long j3 = 8 + j2;
            if ((1 & j2) != 0) {
                j3 = 9 + j2;
            }
            if (j3 > 2147483647L) {
                throw zzaz.b("Chunk is too large (~2GB+) to skip; id: " + i3);
            }
            p2.p((int) j3);
            c2426o3A = C2426o3.a(p2, kn);
        }
    }

    public static void x(int i2, long j2, String str, int i3, PriorityQueue priorityQueue) {
        R5 r5 = new R5(i3, j2, str);
        if ((priorityQueue.size() != i2 || (((R5) priorityQueue.peek()).c <= i3 && ((R5) priorityQueue.peek()).a <= j2)) && !priorityQueue.contains(r5)) {
            priorityQueue.add(r5);
            if (priorityQueue.size() > i2) {
                priorityQueue.poll();
            }
        }
    }

    public static void y(Bundle bundle, String str, List list) {
        if (list != null) {
            bundle.putStringArrayList(str, new ArrayList<>(list));
        }
    }

    public static void z(com.google.common.util.concurrent.e eVar, Pq pq) {
        if (((Boolean) R7.c.o()).booleanValue()) {
            Nv nvT = Nv.t(eVar);
            C2883yp c2883yp = new C2883yp(pq, 2);
            nvT.a(new Qv(0, nvT, c2883yp), AbstractC2270kd.g);
        }
    }
}
