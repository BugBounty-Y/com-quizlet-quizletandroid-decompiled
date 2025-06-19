package com.google.android.gms.internal.ads;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* renamed from: com.google.android.gms.internal.ads.l2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2296l2 implements InterfaceC1818a2 {
    public static final Pattern g = Pattern.compile("(?:(\\d+):)?(\\d+):(\\d+)[:.](\\d+)");
    public final boolean a;
    public final androidx.recyclerview.widget.P0 b;
    public LinkedHashMap d;
    public float e = -3.4028235E38f;
    public float f = -3.4028235E38f;
    public final Kn c = new Kn();

    public C2296l2(List list) throws NumberFormatException {
        if (list == null || list.isEmpty()) {
            this.a = false;
            this.b = null;
            return;
        }
        this.a = true;
        byte[] bArr = (byte[]) list.get(0);
        Charset charset = StandardCharsets.UTF_8;
        String str = new String(bArr, charset);
        AbstractC1795We.B(str.startsWith("Format:"));
        androidx.recyclerview.widget.P0 p0B = androidx.recyclerview.widget.P0.b(str);
        p0B.getClass();
        this.b = p0B;
        d(new Kn((byte[]) list.get(1)), charset);
    }

    public static int b(long j, ArrayList arrayList, ArrayList arrayList2) {
        int i;
        int size = arrayList.size();
        while (true) {
            size--;
            if (size < 0) {
                i = 0;
                break;
            }
            if (((Long) arrayList.get(size)).longValue() == j) {
                return size;
            }
            if (((Long) arrayList.get(size)).longValue() < j) {
                i = size + 1;
                break;
            }
        }
        arrayList.add(i, Long.valueOf(j));
        arrayList2.add(i, i == 0 ? new ArrayList() : new ArrayList((Collection) arrayList2.get(i - 1)));
        return i;
    }

    public static long c(String str) {
        Matcher matcher = g.matcher(str.trim());
        if (!matcher.matches()) {
            return -9223372036854775807L;
        }
        String strGroup = matcher.group(1);
        String str2 = Yo.a;
        long j = Long.parseLong(strGroup) * 3600000000L;
        long j2 = Long.parseLong(matcher.group(2)) * 60000000;
        return j + j2 + (Long.parseLong(matcher.group(3)) * 1000000) + (Long.parseLong(matcher.group(4)) * 10000);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to find 'out' block for switch in B:72:0x018a. Please report as an issue. */
    /* JADX WARN: Removed duplicated region for block: B:177:0x0380  */
    /* JADX WARN: Removed duplicated region for block: B:209:0x03a5 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x016d  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x017b A[Catch: RuntimeException -> 0x01a9, TRY_LEAVE, TryCatch #4 {RuntimeException -> 0x01a9, blocks: (B:67:0x016f, B:69:0x017b, B:71:0x0182, B:75:0x019b, B:73:0x018d), top: B:193:0x016f }] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x019c  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x01a0  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x01a9  */
    @Override // com.google.android.gms.internal.ads.InterfaceC1818a2
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(byte[] r31, int r32, int r33, androidx.camera.core.impl.C0186z r34) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 1040
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2296l2.a(byte[], int, int, androidx.camera.core.impl.z):void");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:142:0x0271  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x0286  */
    /* JADX WARN: Removed duplicated region for block: B:154:0x029b  */
    /* JADX WARN: Removed duplicated region for block: B:160:0x02b0  */
    /* JADX WARN: Removed duplicated region for block: B:163:0x02b6 A[Catch: RuntimeException -> 0x020c, TRY_LEAVE, TryCatch #3 {RuntimeException -> 0x020c, blocks: (B:111:0x01dc, B:113:0x01ea, B:114:0x01f0, B:121:0x0211, B:123:0x0215, B:125:0x0224, B:127:0x0228, B:129:0x0237, B:131:0x023b, B:132:0x0241, B:137:0x025e, B:139:0x0262, B:143:0x0273, B:145:0x0277, B:149:0x0288, B:151:0x028c, B:155:0x029d, B:157:0x02a1, B:161:0x02b2, B:163:0x02b6, B:164:0x02bc, B:171:0x02db, B:169:0x02cc, B:135:0x0249, B:116:0x01fb), top: B:193:0x01dc, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:170:0x02d9  */
    /* JADX WARN: Removed duplicated region for block: B:175:0x02f9  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0158  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void d(com.google.android.gms.internal.ads.Kn r40, java.nio.charset.Charset r41) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 898
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2296l2.d(com.google.android.gms.internal.ads.Kn, java.nio.charset.Charset):void");
    }
}
