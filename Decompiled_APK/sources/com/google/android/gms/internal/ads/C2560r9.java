package com.google.android.gms.internal.ads;

import androidx.collection.C0208f;
import java.util.Collections;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.r9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2560r9 implements InterfaceC2389n9 {
    public static final Map d;
    public final com.google.android.gms.ads.internal.a a;
    public final C2397nb b;
    public final Os c;

    static {
        String[] strArr = {"resize", "playVideo", "storePicture", "createCalendarEvent", "setOrientationProperties", "closeResizedAd", "unload"};
        Integer[] numArr = {1, 2, 3, 4, 5, 6, 7};
        C0208f c0208f = new C0208f(7);
        for (int i = 0; i < 7; i++) {
            c0208f.put(strArr[i], numArr[i]);
        }
        d = Collections.unmodifiableMap(c0208f);
    }

    public C2560r9(com.google.android.gms.ads.internal.a aVar, C2397nb c2397nb, Os os) {
        this.a = aVar;
        this.b = c2397nb;
        this.c = os;
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:173:0x034b A[PHI: r16
  0x034b: PHI (r16v13 int) = (r16v6 int), (r16v7 int), (r16v8 int), (r16v9 int), (r16v10 int), (r16v11 int), (r16v14 int) binds: [B:171:0x0347, B:168:0x033a, B:165:0x032e, B:162:0x0322, B:159:0x0316, B:156:0x030a, B:154:0x02ff] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:218:0x0434 A[Catch: all -> 0x01ac, TryCatch #1 {all -> 0x01ac, blocks: (B:89:0x01a1, B:91:0x01a5, B:92:0x01aa, B:96:0x01af, B:98:0x01b9, B:99:0x01be, B:101:0x01c0, B:103:0x01cc, B:104:0x01d1, B:106:0x01d3, B:108:0x01db, B:109:0x01e0, B:111:0x01e2, B:113:0x01f0, B:114:0x0202, B:116:0x0210, B:117:0x0222, B:119:0x0230, B:120:0x0242, B:122:0x0250, B:123:0x0262, B:125:0x0270, B:126:0x027e, B:128:0x028c, B:129:0x028e, B:131:0x0292, B:133:0x0296, B:135:0x029c, B:138:0x02a4, B:142:0x02da, B:148:0x02e8, B:218:0x0434, B:219:0x0439, B:221:0x043b, B:223:0x045f, B:225:0x0463, B:227:0x046c, B:229:0x049b, B:260:0x0552, B:267:0x0585, B:268:0x059e, B:269:0x05c5, B:271:0x05cd, B:272:0x05dc, B:273:0x0600, B:276:0x0603, B:278:0x0621, B:279:0x0630, B:261:0x0559, B:262:0x0560, B:263:0x0569, B:264:0x0570, B:265:0x0576, B:266:0x057f, B:228:0x0498, B:281:0x0632, B:282:0x0637, B:150:0x02f2, B:152:0x02f6, B:183:0x035b, B:184:0x0365, B:193:0x03b8, B:195:0x03bc, B:197:0x03c0, B:200:0x03c8, B:185:0x0369, B:186:0x0373, B:187:0x037a, B:188:0x0386, B:189:0x038e, B:190:0x03a2, B:191:0x03ae, B:201:0x03d7, B:208:0x040f, B:214:0x041f, B:211:0x0415, B:213:0x041d, B:204:0x0406, B:206:0x040c, B:215:0x0424, B:216:0x042b, B:284:0x0639, B:285:0x063e, B:287:0x0640, B:288:0x0645), top: B:315:0x01a1, inners: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:221:0x043b A[Catch: all -> 0x01ac, TryCatch #1 {all -> 0x01ac, blocks: (B:89:0x01a1, B:91:0x01a5, B:92:0x01aa, B:96:0x01af, B:98:0x01b9, B:99:0x01be, B:101:0x01c0, B:103:0x01cc, B:104:0x01d1, B:106:0x01d3, B:108:0x01db, B:109:0x01e0, B:111:0x01e2, B:113:0x01f0, B:114:0x0202, B:116:0x0210, B:117:0x0222, B:119:0x0230, B:120:0x0242, B:122:0x0250, B:123:0x0262, B:125:0x0270, B:126:0x027e, B:128:0x028c, B:129:0x028e, B:131:0x0292, B:133:0x0296, B:135:0x029c, B:138:0x02a4, B:142:0x02da, B:148:0x02e8, B:218:0x0434, B:219:0x0439, B:221:0x043b, B:223:0x045f, B:225:0x0463, B:227:0x046c, B:229:0x049b, B:260:0x0552, B:267:0x0585, B:268:0x059e, B:269:0x05c5, B:271:0x05cd, B:272:0x05dc, B:273:0x0600, B:276:0x0603, B:278:0x0621, B:279:0x0630, B:261:0x0559, B:262:0x0560, B:263:0x0569, B:264:0x0570, B:265:0x0576, B:266:0x057f, B:228:0x0498, B:281:0x0632, B:282:0x0637, B:150:0x02f2, B:152:0x02f6, B:183:0x035b, B:184:0x0365, B:193:0x03b8, B:195:0x03bc, B:197:0x03c0, B:200:0x03c8, B:185:0x0369, B:186:0x0373, B:187:0x037a, B:188:0x0386, B:189:0x038e, B:190:0x03a2, B:191:0x03ae, B:201:0x03d7, B:208:0x040f, B:214:0x041f, B:211:0x0415, B:213:0x041d, B:204:0x0406, B:206:0x040c, B:215:0x0424, B:216:0x042b, B:284:0x0639, B:285:0x063e, B:287:0x0640, B:288:0x0645), top: B:315:0x01a1, inners: #0 }] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(java.lang.Object r18, java.util.Map r19) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 1744
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2560r9.e(java.lang.Object, java.util.Map):void");
    }
}
