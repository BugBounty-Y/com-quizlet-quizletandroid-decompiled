package com.google.android.gms.internal.ads;

import androidx.camera.core.impl.C0186z;
import java.util.regex.Pattern;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

/* renamed from: com.google.android.gms.internal.ads.t2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2639t2 implements InterfaceC1818a2 {
    public static final Pattern b = Pattern.compile("^([0-9][0-9]+):([0-9][0-9]):([0-9][0-9])(?:(\\.[0-9]+)|:([0-9][0-9])(?:\\.([0-9]+))?)?$");
    public static final Pattern c = Pattern.compile("^([0-9]+(?:\\.[0-9]+)?)(h|m|s|ms|f|t)$");
    public static final Pattern d = Pattern.compile("^(([0-9]*.)?[0-9]+)(px|em|%)$");
    public static final Pattern e = Pattern.compile("^([-+]?\\d+\\.?\\d*?)%$");
    public static final Pattern f = Pattern.compile("^([-+]?\\d+\\.?\\d*?)% ([-+]?\\d+\\.?\\d*?)%$");
    public static final Pattern g = Pattern.compile("^([-+]?\\d+\\.?\\d*?)px ([-+]?\\d+\\.?\\d*?)px$");
    public static final Pattern h = Pattern.compile("^(\\d+) (\\d+)$");
    public static final androidx.viewpager2.widget.c i = new androidx.viewpager2.widget.c(1, 30.0f, 1);
    public final XmlPullParserFactory a;

    public C2639t2() throws XmlPullParserException {
        try {
            XmlPullParserFactory xmlPullParserFactoryNewInstance = XmlPullParserFactory.newInstance();
            this.a = xmlPullParserFactoryNewInstance;
            xmlPullParserFactoryNewInstance.setNamespaceAware(true);
        } catch (XmlPullParserException e2) {
            throw new RuntimeException("Couldn't create XmlPullParserFactory instance", e2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x00f2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static long c(java.lang.String r13, androidx.viewpager2.widget.c r14) throws java.lang.NumberFormatException, com.google.android.gms.internal.ads.zzakh {
        /*
            Method dump skipped, instructions count: 298
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2639t2.c(java.lang.String, androidx.viewpager2.widget.c):long");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0042  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.text.Layout.Alignment d(java.lang.String r5) {
        /*
            java.lang.String r5 = com.google.android.gms.internal.ads.AbstractC2543qs.f(r5)
            int r0 = r5.hashCode()
            r1 = 4
            r2 = 3
            r3 = 2
            r4 = 1
            switch(r0) {
                case -1364013995: goto L38;
                case 100571: goto L2e;
                case 3317767: goto L24;
                case 108511772: goto L1a;
                case 109757538: goto L10;
                default: goto Lf;
            }
        Lf:
            goto L42
        L10:
            java.lang.String r0 = "start"
            boolean r5 = r5.equals(r0)
            if (r5 == 0) goto L42
            r5 = r4
            goto L43
        L1a:
            java.lang.String r0 = "right"
            boolean r5 = r5.equals(r0)
            if (r5 == 0) goto L42
            r5 = r3
            goto L43
        L24:
            java.lang.String r0 = "left"
            boolean r5 = r5.equals(r0)
            if (r5 == 0) goto L42
            r5 = 0
            goto L43
        L2e:
            java.lang.String r0 = "end"
            boolean r5 = r5.equals(r0)
            if (r5 == 0) goto L42
            r5 = r2
            goto L43
        L38:
            java.lang.String r0 = "center"
            boolean r5 = r5.equals(r0)
            if (r5 == 0) goto L42
            r5 = r1
            goto L43
        L42:
            r5 = -1
        L43:
            if (r5 == 0) goto L55
            if (r5 == r4) goto L55
            if (r5 == r3) goto L52
            if (r5 == r2) goto L52
            if (r5 == r1) goto L4f
            r5 = 0
            return r5
        L4f:
            android.text.Layout$Alignment r5 = android.text.Layout.Alignment.ALIGN_CENTER
            return r5
        L52:
            android.text.Layout$Alignment r5 = android.text.Layout.Alignment.ALIGN_OPPOSITE
            return r5
        L55:
            android.text.Layout$Alignment r5 = android.text.Layout.Alignment.ALIGN_NORMAL
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2639t2.d(java.lang.String):android.text.Layout$Alignment");
    }

    public static C2725v2 e(C2725v2 c2725v2) {
        return c2725v2 == null ? new C2725v2() : c2725v2;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:101:0x01b1  */
    /* JADX WARN: Removed duplicated region for block: B:104:0x01be  */
    /* JADX WARN: Removed duplicated region for block: B:110:0x01de  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x01e2  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x0243  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x0246  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x024c  */
    /* JADX WARN: Removed duplicated region for block: B:141:0x0253  */
    /* JADX WARN: Removed duplicated region for block: B:159:0x028e  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x02db  */
    /* JADX WARN: Removed duplicated region for block: B:181:0x02de  */
    /* JADX WARN: Removed duplicated region for block: B:184:0x02ea  */
    /* JADX WARN: Removed duplicated region for block: B:206:0x033a  */
    /* JADX WARN: Removed duplicated region for block: B:229:0x038c  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x038f  */
    /* JADX WARN: Removed duplicated region for block: B:234:0x039b  */
    /* JADX WARN: Removed duplicated region for block: B:267:0x0439  */
    /* JADX WARN: Removed duplicated region for block: B:269:0x043c  */
    /* JADX WARN: Removed duplicated region for block: B:275:0x0460 A[Catch: zzakh -> 0x04a8, TryCatch #0 {zzakh -> 0x04a8, blocks: (B:239:0x03d8, B:242:0x03ea, B:245:0x03fc, B:248:0x0404, B:250:0x040a, B:271:0x0440, B:276:0x0462, B:278:0x0468, B:279:0x0470, B:272:0x0443, B:273:0x045c, B:274:0x045d, B:275:0x0460, B:280:0x0471, B:281:0x0472, B:282:0x048b, B:244:0x03f1, B:283:0x048c, B:284:0x04a7), top: B:300:0x03d8 }] */
    /* JADX WARN: Removed duplicated region for block: B:278:0x0468 A[Catch: zzakh -> 0x04a8, TryCatch #0 {zzakh -> 0x04a8, blocks: (B:239:0x03d8, B:242:0x03ea, B:245:0x03fc, B:248:0x0404, B:250:0x040a, B:271:0x0440, B:276:0x0462, B:278:0x0468, B:279:0x0470, B:272:0x0443, B:273:0x045c, B:274:0x045d, B:275:0x0460, B:280:0x0471, B:281:0x0472, B:282:0x048b, B:244:0x03f1, B:283:0x048c, B:284:0x04a7), top: B:300:0x03d8 }] */
    /* JADX WARN: Removed duplicated region for block: B:313:0x0470 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00dc  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x01a8  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x01ab  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.C2725v2 f(org.xmlpull.v1.XmlPullParser r17, com.google.android.gms.internal.ads.C2725v2 r18) throws com.google.android.gms.internal.ads.zzakh {
        /*
            Method dump skipped, instructions count: 1424
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2639t2.f(org.xmlpull.v1.XmlPullParser, com.google.android.gms.internal.ads.v2):com.google.android.gms.internal.ads.v2");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1818a2
    public final void a(byte[] bArr, int i2, int i3, C0186z c0186z) {
        LA.k(b(i2, bArr, i3), c0186z);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:252:0x04e3  */
    /* JADX WARN: Removed duplicated region for block: B:254:0x04e6  */
    /* JADX WARN: Removed duplicated region for block: B:256:0x04e9  */
    /* JADX WARN: Removed duplicated region for block: B:258:0x04f5  */
    /* JADX WARN: Removed duplicated region for block: B:262:0x050b A[Catch: IOException -> 0x0093, XmlPullParserException -> 0x0096, TRY_LEAVE, TryCatch #17 {IOException -> 0x0093, XmlPullParserException -> 0x0096, blocks: (B:3:0x0007, B:5:0x005d, B:7:0x006a, B:10:0x0076, B:13:0x0086, B:15:0x008e, B:21:0x009b, B:24:0x00a7, B:28:0x00bb, B:30:0x00d4, B:32:0x00e0, B:33:0x00e4, B:35:0x00f0, B:38:0x00fa, B:73:0x019c, B:91:0x01f9, B:94:0x0209, B:96:0x020f, B:98:0x0217, B:100:0x021f, B:102:0x0227, B:104:0x022f, B:106:0x0237, B:108:0x023d, B:110:0x0245, B:112:0x024d, B:114:0x0253, B:116:0x0259, B:118:0x025f, B:120:0x0267, B:123:0x0270, B:432:0x0799, B:127:0x029e, B:130:0x02a6, B:132:0x02af, B:134:0x02c0, B:136:0x02ca, B:138:0x02d9, B:140:0x02df, B:142:0x02f5, B:144:0x02fb, B:293:0x056b, B:137:0x02d0, B:146:0x030a, B:149:0x0318, B:151:0x031e, B:153:0x0327, B:155:0x032d, B:156:0x0334, B:159:0x033b, B:290:0x055e, B:162:0x034b, B:164:0x0353, B:166:0x0359, B:168:0x0361, B:172:0x036d, B:176:0x0384, B:178:0x038a, B:180:0x0397, B:201:0x0403, B:203:0x0409, B:205:0x040f, B:207:0x0417, B:209:0x041d, B:213:0x042e, B:215:0x0434, B:217:0x0441, B:238:0x04b4, B:240:0x04bc, B:260:0x0501, B:262:0x050b, B:288:0x0551, B:219:0x044c, B:220:0x044d, B:221:0x044e, B:222:0x045b, B:225:0x0463, B:228:0x0471, B:230:0x0477, B:232:0x0482, B:233:0x0492, B:234:0x0493, B:235:0x0494, B:236:0x04a1, B:181:0x03a0, B:182:0x03a1, B:183:0x03a2, B:185:0x03ad, B:188:0x03b7, B:191:0x03c0, B:193:0x03c6, B:195:0x03d1, B:196:0x03e3, B:197:0x03e4, B:198:0x03e5, B:199:0x03ed, B:298:0x058f, B:301:0x05b1, B:365:0x0689, B:335:0x0614, B:337:0x061c, B:342:0x0634, B:345:0x063d, B:348:0x0648, B:350:0x0657, B:403:0x0709, B:349:0x064d, B:360:0x066e, B:363:0x0675, B:364:0x067f, B:370:0x06a0, B:374:0x06ac, B:378:0x06b5, B:386:0x06c7, B:389:0x06d0, B:393:0x06db, B:395:0x06e7, B:397:0x06ec, B:399:0x06f0, B:400:0x06f7, B:76:0x01a5, B:78:0x01af, B:81:0x01ba, B:83:0x01c0, B:85:0x01cb, B:86:0x01d9, B:87:0x01da, B:88:0x01db, B:43:0x0116, B:46:0x0126, B:49:0x0130, B:51:0x0136, B:53:0x013d, B:55:0x0143, B:61:0x015b, B:63:0x0162, B:72:0x0193, B:68:0x0186, B:71:0x0192, B:407:0x072e, B:409:0x073a, B:410:0x0741, B:413:0x074e, B:416:0x0752, B:418:0x075c, B:420:0x0766, B:424:0x0772, B:422:0x076d, B:427:0x0786, B:430:0x0795, B:437:0x07b6), top: B:467:0x0007, inners: #1, #4, #11, #14, #15 }] */
    /* JADX WARN: Removed duplicated region for block: B:279:0x0540  */
    /* JADX WARN: Removed duplicated region for block: B:281:0x0543  */
    /* JADX WARN: Removed duplicated region for block: B:285:0x0549  */
    /* JADX WARN: Removed duplicated region for block: B:287:0x054f  */
    /* JADX WARN: Removed duplicated region for block: B:296:0x0578 A[LOOP:1: B:130:0x02a6->B:296:0x0578, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:323:0x05ff  */
    /* JADX WARN: Removed duplicated region for block: B:397:0x06ec A[Catch: IOException -> 0x0093, XmlPullParserException -> 0x0096, zzakh -> 0x0708, TryCatch #3 {zzakh -> 0x0708, blocks: (B:395:0x06e7, B:397:0x06ec, B:399:0x06f0, B:400:0x06f7), top: B:448:0x06e7 }] */
    /* JADX WARN: Removed duplicated region for block: B:485:0x0571 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01a2  */
    /* JADX WARN: Removed duplicated region for block: B:76:0x01a5 A[Catch: IOException -> 0x0093, XmlPullParserException -> 0x0096, TryCatch #17 {IOException -> 0x0093, XmlPullParserException -> 0x0096, blocks: (B:3:0x0007, B:5:0x005d, B:7:0x006a, B:10:0x0076, B:13:0x0086, B:15:0x008e, B:21:0x009b, B:24:0x00a7, B:28:0x00bb, B:30:0x00d4, B:32:0x00e0, B:33:0x00e4, B:35:0x00f0, B:38:0x00fa, B:73:0x019c, B:91:0x01f9, B:94:0x0209, B:96:0x020f, B:98:0x0217, B:100:0x021f, B:102:0x0227, B:104:0x022f, B:106:0x0237, B:108:0x023d, B:110:0x0245, B:112:0x024d, B:114:0x0253, B:116:0x0259, B:118:0x025f, B:120:0x0267, B:123:0x0270, B:432:0x0799, B:127:0x029e, B:130:0x02a6, B:132:0x02af, B:134:0x02c0, B:136:0x02ca, B:138:0x02d9, B:140:0x02df, B:142:0x02f5, B:144:0x02fb, B:293:0x056b, B:137:0x02d0, B:146:0x030a, B:149:0x0318, B:151:0x031e, B:153:0x0327, B:155:0x032d, B:156:0x0334, B:159:0x033b, B:290:0x055e, B:162:0x034b, B:164:0x0353, B:166:0x0359, B:168:0x0361, B:172:0x036d, B:176:0x0384, B:178:0x038a, B:180:0x0397, B:201:0x0403, B:203:0x0409, B:205:0x040f, B:207:0x0417, B:209:0x041d, B:213:0x042e, B:215:0x0434, B:217:0x0441, B:238:0x04b4, B:240:0x04bc, B:260:0x0501, B:262:0x050b, B:288:0x0551, B:219:0x044c, B:220:0x044d, B:221:0x044e, B:222:0x045b, B:225:0x0463, B:228:0x0471, B:230:0x0477, B:232:0x0482, B:233:0x0492, B:234:0x0493, B:235:0x0494, B:236:0x04a1, B:181:0x03a0, B:182:0x03a1, B:183:0x03a2, B:185:0x03ad, B:188:0x03b7, B:191:0x03c0, B:193:0x03c6, B:195:0x03d1, B:196:0x03e3, B:197:0x03e4, B:198:0x03e5, B:199:0x03ed, B:298:0x058f, B:301:0x05b1, B:365:0x0689, B:335:0x0614, B:337:0x061c, B:342:0x0634, B:345:0x063d, B:348:0x0648, B:350:0x0657, B:403:0x0709, B:349:0x064d, B:360:0x066e, B:363:0x0675, B:364:0x067f, B:370:0x06a0, B:374:0x06ac, B:378:0x06b5, B:386:0x06c7, B:389:0x06d0, B:393:0x06db, B:395:0x06e7, B:397:0x06ec, B:399:0x06f0, B:400:0x06f7, B:76:0x01a5, B:78:0x01af, B:81:0x01ba, B:83:0x01c0, B:85:0x01cb, B:86:0x01d9, B:87:0x01da, B:88:0x01db, B:43:0x0116, B:46:0x0126, B:49:0x0130, B:51:0x0136, B:53:0x013d, B:55:0x0143, B:61:0x015b, B:63:0x0162, B:72:0x0193, B:68:0x0186, B:71:0x0192, B:407:0x072e, B:409:0x073a, B:410:0x0741, B:413:0x074e, B:416:0x0752, B:418:0x075c, B:420:0x0766, B:424:0x0772, B:422:0x076d, B:427:0x0786, B:430:0x0795, B:437:0x07b6), top: B:467:0x0007, inners: #1, #4, #11, #14, #15 }] */
    /* JADX WARN: Type inference failed for: r48v1, types: [com.google.android.gms.internal.ads.v2, java.lang.Throwable] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.quizlet.data.interactor.folderwithcreator.m b(int r47, byte[] r48, int r49) throws org.xmlpull.v1.XmlPullParserException, java.lang.NumberFormatException, java.io.IOException, com.google.android.gms.internal.ads.zzakh {
        /*
            Method dump skipped, instructions count: 2018
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2639t2.b(int, byte[], int):com.quizlet.data.interactor.folderwithcreator.m");
    }
}
