package com.google.android.gms.measurement.internal;

import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import android.net.Uri;
import android.os.Bundle;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;
import androidx.collection.C0208f;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.internal.measurement.C2964a1;
import com.google.android.gms.internal.measurement.C2969b1;
import com.google.android.gms.internal.measurement.C2974c1;
import com.google.android.gms.internal.measurement.C3014k1;
import com.google.android.gms.internal.measurement.C3019l1;
import com.google.android.gms.internal.measurement.C3087z0;
import com.google.android.gms.internal.measurement.E3;
import com.google.android.gms.internal.measurement.zzmm;
import com.j256.ormlite.field.FieldType;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class r1 implements InterfaceC3873i0 {
    public static volatile r1 K;
    public final HashMap B;
    public final HashMap C;
    public final HashMap D;
    public L0 F;
    public String G;
    public f1 H;
    public long I;
    public final T a;
    public final M b;
    public C3874j c;
    public com.android.billingclient.api.C d;
    public k1 e;
    public C3860c f;
    public final M g;
    public M h;
    public a1 i;
    public P k;
    public final Y l;
    public boolean n;
    public long o;
    public ArrayList p;
    public int r;
    public int s;
    public boolean t;
    public boolean u;
    public boolean v;
    public FileLock w;
    public FileChannel x;
    public ArrayList y;
    public ArrayList z;
    public final AtomicBoolean m = new AtomicBoolean(false);
    public final LinkedList q = new LinkedList();
    public final HashMap E = new HashMap();
    public final com.airbnb.lottie.network.c J = new com.airbnb.lottie.network.c(this, 23);
    public long A = -1;
    public final o1 j = new o1(this);

    public r1(s1 s1Var) {
        this.l = Y.q(s1Var.a, null, null);
        M m = new M(this, 2);
        m.U();
        this.g = m;
        M m2 = new M(this, 0);
        m2.U();
        this.b = m2;
        T t = new T(this);
        t.U();
        this.a = t;
        this.B = new HashMap();
        this.C = new HashMap();
        this.D = new HashMap();
        i().c0(new com.google.android.gms.common.api.internal.w(this, s1Var));
    }

    public static String B(String str, Map map) {
        if (map == null) {
            return null;
        }
        for (Map.Entry entry : map.entrySet()) {
            if (str.equalsIgnoreCase((String) entry.getKey())) {
                if (((List) entry.getValue()).isEmpty()) {
                    return null;
                }
                return (String) ((List) entry.getValue()).get(0);
            }
        }
        return null;
    }

    public static final boolean K(zzr zzrVar) {
        return (TextUtils.isEmpty(zzrVar.b) && TextUtils.isEmpty(zzrVar.p)) ? false : true;
    }

    public static final void L(m1 m1Var) {
        if (m1Var == null) {
            throw new IllegalStateException("Upload Component not created");
        }
        if (!m1Var.d) {
            throw new IllegalStateException("Component not initialized: ".concat(String.valueOf(m1Var.getClass())));
        }
    }

    public static final Boolean M(zzr zzrVar) {
        Boolean bool = zzrVar.q;
        String str = zzrVar.E;
        if (!TextUtils.isEmpty(str)) {
            int iOrdinal = ((EnumC3875j0) com.airbnb.lottie.network.c.B(str).b).ordinal();
            if (iOrdinal == 0 || iOrdinal == 1) {
                return null;
            }
            if (iOrdinal == 2) {
                return Boolean.TRUE;
            }
            if (iOrdinal == 3) {
                return Boolean.FALSE;
            }
        }
        return bool;
    }

    public static r1 o0(Context context) {
        com.google.android.gms.common.internal.u.h(context);
        com.google.android.gms.common.internal.u.h(context.getApplicationContext());
        if (K == null) {
            synchronized (r1.class) {
                try {
                    if (K == null) {
                        K = new r1(new s1(context));
                    }
                } finally {
                }
            }
        }
        return K;
    }

    public static final void w(com.google.android.gms.internal.measurement.T0 t0, int i, String str) {
        List listP = t0.p();
        for (int i2 = 0; i2 < listP.size(); i2++) {
            if ("_err".equals(((com.google.android.gms.internal.measurement.X0) listP.get(i2)).s())) {
                return;
            }
        }
        com.google.android.gms.internal.measurement.W0 w0R = com.google.android.gms.internal.measurement.X0.r();
        w0R.k("_err");
        w0R.i(i);
        com.google.android.gms.internal.measurement.X0 x0 = (com.google.android.gms.internal.measurement.X0) w0R.f();
        com.google.android.gms.internal.measurement.W0 w0R2 = com.google.android.gms.internal.measurement.X0.r();
        w0R2.k("_ev");
        w0R2.l(str);
        com.google.android.gms.internal.measurement.X0 x02 = (com.google.android.gms.internal.measurement.X0) w0R2.f();
        t0.m(x0);
        t0.m(x02);
    }

    public static final void x(com.google.android.gms.internal.measurement.T0 t0, String str) {
        List listP = t0.p();
        for (int i = 0; i < listP.size(); i++) {
            if (str.equals(((com.google.android.gms.internal.measurement.X0) listP.get(i)).s())) {
                t0.h();
                com.google.android.gms.internal.measurement.U0.y((com.google.android.gms.internal.measurement.U0) t0.b, i);
                return;
            }
        }
    }

    public final Boolean A(F f) {
        try {
            long jS = f.S();
            Y y = this.l;
            if (jS != -2147483648L) {
                if (f.S() == com.google.android.gms.common.wrappers.c.a(y.a).c(f.c(), 0).versionCode) {
                    return Boolean.TRUE;
                }
            } else {
                String str = com.google.android.gms.common.wrappers.c.a(y.a).c(f.c(), 0).versionName;
                String strE = f.e();
                if (strE != null && strE.equals(str)) {
                    return Boolean.TRUE;
                }
            }
            return Boolean.FALSE;
        } catch (PackageManager.NameNotFoundException unused) {
            return null;
        }
    }

    public final void C() {
        i().S();
        if (this.t || this.u || this.v) {
            I iC = c();
            iC.o.i("Not stopping services. fetch, network, upload", Boolean.valueOf(this.t), Boolean.valueOf(this.u), Boolean.valueOf(this.v));
            return;
        }
        c().o.f("Stopping uploading service(s)");
        ArrayList arrayList = this.p;
        if (arrayList == null) {
            return;
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            ((Runnable) it2.next()).run();
        }
        ArrayList arrayList2 = this.p;
        com.google.android.gms.common.internal.u.h(arrayList2);
        arrayList2.clear();
    }

    public final void D(C2969b1 c2969b1, long j, boolean z) {
        v1 v1Var;
        Object obj;
        String str = true != z ? "_lte" : "_se";
        C3874j c3874j = this.c;
        L(c3874j);
        v1 v1VarY0 = c3874j.Y0(c2969b1.z(), str);
        if (v1VarY0 == null || (obj = v1VarY0.e) == null) {
            String strZ = c2969b1.z();
            ((com.google.android.gms.common.util.b) f()).getClass();
            v1Var = new v1(strZ, "auto", str, System.currentTimeMillis(), Long.valueOf(j));
        } else {
            String strZ2 = c2969b1.z();
            ((com.google.android.gms.common.util.b) f()).getClass();
            v1Var = new v1(strZ2, "auto", str, System.currentTimeMillis(), Long.valueOf(((Long) obj).longValue() + j));
        }
        C3014k1 c3014k1R = C3019l1.r();
        c3014k1R.h();
        C3019l1.z((C3019l1) c3014k1R.b, str);
        ((com.google.android.gms.common.util.b) f()).getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        c3014k1R.h();
        C3019l1.A((C3019l1) c3014k1R.b, jCurrentTimeMillis);
        Object obj2 = v1Var.e;
        long jLongValue = ((Long) obj2).longValue();
        c3014k1R.h();
        C3019l1.y((C3019l1) c3014k1R.b, jLongValue);
        C3019l1 c3019l1 = (C3019l1) c3014k1R.f();
        int iM0 = M.m0(c2969b1, str);
        if (iM0 >= 0) {
            c2969b1.h();
            C2974c1.D1((C2974c1) c2969b1.b, iM0, c3019l1);
        } else {
            c2969b1.h();
            C2974c1.r0((C2974c1) c2969b1.b, c3019l1);
        }
        if (j > 0) {
            C3874j c3874j2 = this.c;
            L(c3874j2);
            c3874j2.G0(v1Var);
            c().o.h("Updated engagement user property. scope, value", true != z ? "lifetime" : "session-scoped", obj2);
        }
    }

    public final void E() {
        i().S();
        if (this.q.isEmpty()) {
            return;
        }
        if (this.H == null) {
            this.H = new f1(this, this.l, 2);
        }
        if (this.H.c != 0) {
            return;
        }
        ((com.google.android.gms.common.util.b) f()).getClass();
        long jMax = Math.max(0L, ((Integer) AbstractC3893t.A0.a(null)).intValue() - (SystemClock.elapsedRealtime() - this.I));
        c().o.g("Scheduling notify next app runnable, delay in ms", Long.valueOf(jMax));
        if (this.H == null) {
            this.H = new f1(this, this.l, 2);
        }
        this.H.c(jMax);
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x031d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void F() {
        /*
            Method dump skipped, instructions count: 965
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.F():void");
    }

    /* JADX WARN: Removed duplicated region for block: B:117:0x0416 A[Catch: all -> 0x0117, TryCatch #3 {all -> 0x0117, blocks: (B:3:0x0012, B:5:0x002a, B:8:0x0033, B:9:0x0052, B:12:0x0070, B:15:0x009a, B:17:0x00d7, B:20:0x00f0, B:22:0x00fa, B:208:0x06eb, B:27:0x012f, B:29:0x0141, B:32:0x0151, B:34:0x0157, B:38:0x0161, B:40:0x016e, B:42:0x017c, B:44:0x0182, B:48:0x018d, B:49:0x019b, B:51:0x01ad, B:54:0x01d4, B:56:0x01de, B:58:0x01ee, B:60:0x01fc, B:62:0x020c, B:63:0x0217, B:64:0x021a, B:67:0x0232, B:76:0x0263, B:79:0x0271, B:81:0x027f, B:86:0x02db, B:82:0x02a3, B:84:0x02b3, B:90:0x02ea, B:92:0x0314, B:93:0x033c, B:95:0x0371, B:97:0x0377, B:100:0x0383, B:102:0x03b8, B:103:0x03d5, B:105:0x03df, B:107:0x03ed, B:111:0x0401, B:108:0x03f5, B:114:0x0408, B:117:0x0416, B:118:0x0435, B:120:0x0450, B:121:0x045c, B:124:0x0466, B:130:0x0489, B:127:0x0478, B:133:0x0490, B:135:0x049c, B:137:0x04a8, B:148:0x04f1, B:140:0x04c9, B:143:0x04db, B:145:0x04e1, B:147:0x04eb, B:149:0x050e, B:151:0x051a, B:154:0x052b, B:156:0x053c, B:158:0x0548, B:174:0x05a2, B:176:0x05ac, B:177:0x05b8, B:179:0x05c2, B:181:0x05d2, B:183:0x05dc, B:184:0x05ef, B:186:0x05f5, B:187:0x0610, B:189:0x0616, B:190:0x0634, B:191:0x0643, B:195:0x066e, B:192:0x064b, B:194:0x0659, B:196:0x0676, B:197:0x0695, B:199:0x069b, B:201:0x06ae, B:202:0x06bb, B:203:0x06bf, B:205:0x06c5, B:207:0x06d3, B:162:0x055a, B:164:0x0568, B:167:0x057b, B:169:0x058c, B:171:0x0598, B:211:0x0704, B:213:0x0716, B:215:0x071f, B:226:0x074e, B:216:0x0725, B:218:0x072e, B:220:0x0734, B:223:0x0740, B:225:0x0748, B:227:0x0751, B:228:0x075d, B:231:0x0765, B:233:0x0777, B:234:0x0782, B:236:0x078a, B:240:0x07b9, B:242:0x07d5, B:244:0x07ea, B:246:0x0806, B:248:0x081b, B:249:0x0837, B:251:0x083d, B:253:0x0855, B:254:0x0863, B:256:0x0873, B:257:0x0881, B:258:0x0886, B:260:0x08d0, B:262:0x08d6, B:268:0x0901, B:270:0x0909, B:271:0x0927, B:273:0x092d, B:274:0x0941, B:276:0x0958, B:278:0x0969, B:280:0x097b, B:282:0x0985, B:283:0x0988, B:285:0x09e3, B:286:0x09f6, B:289:0x09fe, B:292:0x0a1d, B:294:0x0a36, B:296:0x0a4b, B:298:0x0a50, B:300:0x0a54, B:302:0x0a58, B:304:0x0a62, B:305:0x0a68, B:307:0x0a6c, B:309:0x0a72, B:310:0x0a7e, B:311:0x0a87, B:376:0x0cf8, B:313:0x0a92, B:315:0x0aaa, B:320:0x0ad2, B:322:0x0af9, B:323:0x0b01, B:325:0x0b07, B:327:0x0b17, B:334:0x0b41, B:335:0x0b64, B:337:0x0b70, B:339:0x0b86, B:340:0x0bc6, B:346:0x0be0, B:348:0x0beb, B:350:0x0bef, B:352:0x0bf3, B:354:0x0bf7, B:355:0x0c03, B:356:0x0c08, B:358:0x0c0e, B:360:0x0c24, B:361:0x0c29, B:375:0x0cf3, B:362:0x0c67, B:364:0x0c6b, B:368:0x0c7f, B:370:0x0ca1, B:371:0x0ca8, B:374:0x0ce7, B:365:0x0c70, B:332:0x0b2b, B:318:0x0ab6, B:377:0x0d00, B:379:0x0d0e, B:380:0x0d22, B:381:0x0d2a, B:383:0x0d30, B:385:0x0d48, B:387:0x0d5a, B:407:0x0e09, B:409:0x0e0f, B:411:0x0e26, B:414:0x0e2d, B:419:0x0e6e, B:421:0x0e76, B:423:0x0eb4, B:426:0x0ee8, B:427:0x0eec, B:428:0x0ef6, B:430:0x0f37, B:431:0x0f44, B:433:0x0f53, B:436:0x0f6a, B:438:0x0f81, B:425:0x0ec7, B:415:0x0e3c, B:417:0x0e4a, B:418:0x0e55, B:439:0x0f96, B:440:0x0fa9, B:444:0x0fc9, B:443:0x0fb4, B:388:0x0d75, B:390:0x0d7b, B:392:0x0d8b, B:394:0x0d92, B:400:0x0da8, B:402:0x0daf, B:404:0x0dfa, B:406:0x0e01, B:405:0x0dfe, B:401:0x0dac, B:393:0x0d8f, B:263:0x08e6, B:265:0x08ec, B:267:0x08f2, B:247:0x0818, B:243:0x07e7, B:237:0x0790, B:239:0x0796, B:445:0x0fd3), top: B:457:0x0012, inners: #0, #1, #2, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:118:0x0435 A[Catch: all -> 0x0117, TryCatch #3 {all -> 0x0117, blocks: (B:3:0x0012, B:5:0x002a, B:8:0x0033, B:9:0x0052, B:12:0x0070, B:15:0x009a, B:17:0x00d7, B:20:0x00f0, B:22:0x00fa, B:208:0x06eb, B:27:0x012f, B:29:0x0141, B:32:0x0151, B:34:0x0157, B:38:0x0161, B:40:0x016e, B:42:0x017c, B:44:0x0182, B:48:0x018d, B:49:0x019b, B:51:0x01ad, B:54:0x01d4, B:56:0x01de, B:58:0x01ee, B:60:0x01fc, B:62:0x020c, B:63:0x0217, B:64:0x021a, B:67:0x0232, B:76:0x0263, B:79:0x0271, B:81:0x027f, B:86:0x02db, B:82:0x02a3, B:84:0x02b3, B:90:0x02ea, B:92:0x0314, B:93:0x033c, B:95:0x0371, B:97:0x0377, B:100:0x0383, B:102:0x03b8, B:103:0x03d5, B:105:0x03df, B:107:0x03ed, B:111:0x0401, B:108:0x03f5, B:114:0x0408, B:117:0x0416, B:118:0x0435, B:120:0x0450, B:121:0x045c, B:124:0x0466, B:130:0x0489, B:127:0x0478, B:133:0x0490, B:135:0x049c, B:137:0x04a8, B:148:0x04f1, B:140:0x04c9, B:143:0x04db, B:145:0x04e1, B:147:0x04eb, B:149:0x050e, B:151:0x051a, B:154:0x052b, B:156:0x053c, B:158:0x0548, B:174:0x05a2, B:176:0x05ac, B:177:0x05b8, B:179:0x05c2, B:181:0x05d2, B:183:0x05dc, B:184:0x05ef, B:186:0x05f5, B:187:0x0610, B:189:0x0616, B:190:0x0634, B:191:0x0643, B:195:0x066e, B:192:0x064b, B:194:0x0659, B:196:0x0676, B:197:0x0695, B:199:0x069b, B:201:0x06ae, B:202:0x06bb, B:203:0x06bf, B:205:0x06c5, B:207:0x06d3, B:162:0x055a, B:164:0x0568, B:167:0x057b, B:169:0x058c, B:171:0x0598, B:211:0x0704, B:213:0x0716, B:215:0x071f, B:226:0x074e, B:216:0x0725, B:218:0x072e, B:220:0x0734, B:223:0x0740, B:225:0x0748, B:227:0x0751, B:228:0x075d, B:231:0x0765, B:233:0x0777, B:234:0x0782, B:236:0x078a, B:240:0x07b9, B:242:0x07d5, B:244:0x07ea, B:246:0x0806, B:248:0x081b, B:249:0x0837, B:251:0x083d, B:253:0x0855, B:254:0x0863, B:256:0x0873, B:257:0x0881, B:258:0x0886, B:260:0x08d0, B:262:0x08d6, B:268:0x0901, B:270:0x0909, B:271:0x0927, B:273:0x092d, B:274:0x0941, B:276:0x0958, B:278:0x0969, B:280:0x097b, B:282:0x0985, B:283:0x0988, B:285:0x09e3, B:286:0x09f6, B:289:0x09fe, B:292:0x0a1d, B:294:0x0a36, B:296:0x0a4b, B:298:0x0a50, B:300:0x0a54, B:302:0x0a58, B:304:0x0a62, B:305:0x0a68, B:307:0x0a6c, B:309:0x0a72, B:310:0x0a7e, B:311:0x0a87, B:376:0x0cf8, B:313:0x0a92, B:315:0x0aaa, B:320:0x0ad2, B:322:0x0af9, B:323:0x0b01, B:325:0x0b07, B:327:0x0b17, B:334:0x0b41, B:335:0x0b64, B:337:0x0b70, B:339:0x0b86, B:340:0x0bc6, B:346:0x0be0, B:348:0x0beb, B:350:0x0bef, B:352:0x0bf3, B:354:0x0bf7, B:355:0x0c03, B:356:0x0c08, B:358:0x0c0e, B:360:0x0c24, B:361:0x0c29, B:375:0x0cf3, B:362:0x0c67, B:364:0x0c6b, B:368:0x0c7f, B:370:0x0ca1, B:371:0x0ca8, B:374:0x0ce7, B:365:0x0c70, B:332:0x0b2b, B:318:0x0ab6, B:377:0x0d00, B:379:0x0d0e, B:380:0x0d22, B:381:0x0d2a, B:383:0x0d30, B:385:0x0d48, B:387:0x0d5a, B:407:0x0e09, B:409:0x0e0f, B:411:0x0e26, B:414:0x0e2d, B:419:0x0e6e, B:421:0x0e76, B:423:0x0eb4, B:426:0x0ee8, B:427:0x0eec, B:428:0x0ef6, B:430:0x0f37, B:431:0x0f44, B:433:0x0f53, B:436:0x0f6a, B:438:0x0f81, B:425:0x0ec7, B:415:0x0e3c, B:417:0x0e4a, B:418:0x0e55, B:439:0x0f96, B:440:0x0fa9, B:444:0x0fc9, B:443:0x0fb4, B:388:0x0d75, B:390:0x0d7b, B:392:0x0d8b, B:394:0x0d92, B:400:0x0da8, B:402:0x0daf, B:404:0x0dfa, B:406:0x0e01, B:405:0x0dfe, B:401:0x0dac, B:393:0x0d8f, B:263:0x08e6, B:265:0x08ec, B:267:0x08f2, B:247:0x0818, B:243:0x07e7, B:237:0x0790, B:239:0x0796, B:445:0x0fd3), top: B:457:0x0012, inners: #0, #1, #2, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0450 A[Catch: all -> 0x0117, TryCatch #3 {all -> 0x0117, blocks: (B:3:0x0012, B:5:0x002a, B:8:0x0033, B:9:0x0052, B:12:0x0070, B:15:0x009a, B:17:0x00d7, B:20:0x00f0, B:22:0x00fa, B:208:0x06eb, B:27:0x012f, B:29:0x0141, B:32:0x0151, B:34:0x0157, B:38:0x0161, B:40:0x016e, B:42:0x017c, B:44:0x0182, B:48:0x018d, B:49:0x019b, B:51:0x01ad, B:54:0x01d4, B:56:0x01de, B:58:0x01ee, B:60:0x01fc, B:62:0x020c, B:63:0x0217, B:64:0x021a, B:67:0x0232, B:76:0x0263, B:79:0x0271, B:81:0x027f, B:86:0x02db, B:82:0x02a3, B:84:0x02b3, B:90:0x02ea, B:92:0x0314, B:93:0x033c, B:95:0x0371, B:97:0x0377, B:100:0x0383, B:102:0x03b8, B:103:0x03d5, B:105:0x03df, B:107:0x03ed, B:111:0x0401, B:108:0x03f5, B:114:0x0408, B:117:0x0416, B:118:0x0435, B:120:0x0450, B:121:0x045c, B:124:0x0466, B:130:0x0489, B:127:0x0478, B:133:0x0490, B:135:0x049c, B:137:0x04a8, B:148:0x04f1, B:140:0x04c9, B:143:0x04db, B:145:0x04e1, B:147:0x04eb, B:149:0x050e, B:151:0x051a, B:154:0x052b, B:156:0x053c, B:158:0x0548, B:174:0x05a2, B:176:0x05ac, B:177:0x05b8, B:179:0x05c2, B:181:0x05d2, B:183:0x05dc, B:184:0x05ef, B:186:0x05f5, B:187:0x0610, B:189:0x0616, B:190:0x0634, B:191:0x0643, B:195:0x066e, B:192:0x064b, B:194:0x0659, B:196:0x0676, B:197:0x0695, B:199:0x069b, B:201:0x06ae, B:202:0x06bb, B:203:0x06bf, B:205:0x06c5, B:207:0x06d3, B:162:0x055a, B:164:0x0568, B:167:0x057b, B:169:0x058c, B:171:0x0598, B:211:0x0704, B:213:0x0716, B:215:0x071f, B:226:0x074e, B:216:0x0725, B:218:0x072e, B:220:0x0734, B:223:0x0740, B:225:0x0748, B:227:0x0751, B:228:0x075d, B:231:0x0765, B:233:0x0777, B:234:0x0782, B:236:0x078a, B:240:0x07b9, B:242:0x07d5, B:244:0x07ea, B:246:0x0806, B:248:0x081b, B:249:0x0837, B:251:0x083d, B:253:0x0855, B:254:0x0863, B:256:0x0873, B:257:0x0881, B:258:0x0886, B:260:0x08d0, B:262:0x08d6, B:268:0x0901, B:270:0x0909, B:271:0x0927, B:273:0x092d, B:274:0x0941, B:276:0x0958, B:278:0x0969, B:280:0x097b, B:282:0x0985, B:283:0x0988, B:285:0x09e3, B:286:0x09f6, B:289:0x09fe, B:292:0x0a1d, B:294:0x0a36, B:296:0x0a4b, B:298:0x0a50, B:300:0x0a54, B:302:0x0a58, B:304:0x0a62, B:305:0x0a68, B:307:0x0a6c, B:309:0x0a72, B:310:0x0a7e, B:311:0x0a87, B:376:0x0cf8, B:313:0x0a92, B:315:0x0aaa, B:320:0x0ad2, B:322:0x0af9, B:323:0x0b01, B:325:0x0b07, B:327:0x0b17, B:334:0x0b41, B:335:0x0b64, B:337:0x0b70, B:339:0x0b86, B:340:0x0bc6, B:346:0x0be0, B:348:0x0beb, B:350:0x0bef, B:352:0x0bf3, B:354:0x0bf7, B:355:0x0c03, B:356:0x0c08, B:358:0x0c0e, B:360:0x0c24, B:361:0x0c29, B:375:0x0cf3, B:362:0x0c67, B:364:0x0c6b, B:368:0x0c7f, B:370:0x0ca1, B:371:0x0ca8, B:374:0x0ce7, B:365:0x0c70, B:332:0x0b2b, B:318:0x0ab6, B:377:0x0d00, B:379:0x0d0e, B:380:0x0d22, B:381:0x0d2a, B:383:0x0d30, B:385:0x0d48, B:387:0x0d5a, B:407:0x0e09, B:409:0x0e0f, B:411:0x0e26, B:414:0x0e2d, B:419:0x0e6e, B:421:0x0e76, B:423:0x0eb4, B:426:0x0ee8, B:427:0x0eec, B:428:0x0ef6, B:430:0x0f37, B:431:0x0f44, B:433:0x0f53, B:436:0x0f6a, B:438:0x0f81, B:425:0x0ec7, B:415:0x0e3c, B:417:0x0e4a, B:418:0x0e55, B:439:0x0f96, B:440:0x0fa9, B:444:0x0fc9, B:443:0x0fb4, B:388:0x0d75, B:390:0x0d7b, B:392:0x0d8b, B:394:0x0d92, B:400:0x0da8, B:402:0x0daf, B:404:0x0dfa, B:406:0x0e01, B:405:0x0dfe, B:401:0x0dac, B:393:0x0d8f, B:263:0x08e6, B:265:0x08ec, B:267:0x08f2, B:247:0x0818, B:243:0x07e7, B:237:0x0790, B:239:0x0796, B:445:0x0fd3), top: B:457:0x0012, inners: #0, #1, #2, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:151:0x051a A[Catch: all -> 0x0117, TryCatch #3 {all -> 0x0117, blocks: (B:3:0x0012, B:5:0x002a, B:8:0x0033, B:9:0x0052, B:12:0x0070, B:15:0x009a, B:17:0x00d7, B:20:0x00f0, B:22:0x00fa, B:208:0x06eb, B:27:0x012f, B:29:0x0141, B:32:0x0151, B:34:0x0157, B:38:0x0161, B:40:0x016e, B:42:0x017c, B:44:0x0182, B:48:0x018d, B:49:0x019b, B:51:0x01ad, B:54:0x01d4, B:56:0x01de, B:58:0x01ee, B:60:0x01fc, B:62:0x020c, B:63:0x0217, B:64:0x021a, B:67:0x0232, B:76:0x0263, B:79:0x0271, B:81:0x027f, B:86:0x02db, B:82:0x02a3, B:84:0x02b3, B:90:0x02ea, B:92:0x0314, B:93:0x033c, B:95:0x0371, B:97:0x0377, B:100:0x0383, B:102:0x03b8, B:103:0x03d5, B:105:0x03df, B:107:0x03ed, B:111:0x0401, B:108:0x03f5, B:114:0x0408, B:117:0x0416, B:118:0x0435, B:120:0x0450, B:121:0x045c, B:124:0x0466, B:130:0x0489, B:127:0x0478, B:133:0x0490, B:135:0x049c, B:137:0x04a8, B:148:0x04f1, B:140:0x04c9, B:143:0x04db, B:145:0x04e1, B:147:0x04eb, B:149:0x050e, B:151:0x051a, B:154:0x052b, B:156:0x053c, B:158:0x0548, B:174:0x05a2, B:176:0x05ac, B:177:0x05b8, B:179:0x05c2, B:181:0x05d2, B:183:0x05dc, B:184:0x05ef, B:186:0x05f5, B:187:0x0610, B:189:0x0616, B:190:0x0634, B:191:0x0643, B:195:0x066e, B:192:0x064b, B:194:0x0659, B:196:0x0676, B:197:0x0695, B:199:0x069b, B:201:0x06ae, B:202:0x06bb, B:203:0x06bf, B:205:0x06c5, B:207:0x06d3, B:162:0x055a, B:164:0x0568, B:167:0x057b, B:169:0x058c, B:171:0x0598, B:211:0x0704, B:213:0x0716, B:215:0x071f, B:226:0x074e, B:216:0x0725, B:218:0x072e, B:220:0x0734, B:223:0x0740, B:225:0x0748, B:227:0x0751, B:228:0x075d, B:231:0x0765, B:233:0x0777, B:234:0x0782, B:236:0x078a, B:240:0x07b9, B:242:0x07d5, B:244:0x07ea, B:246:0x0806, B:248:0x081b, B:249:0x0837, B:251:0x083d, B:253:0x0855, B:254:0x0863, B:256:0x0873, B:257:0x0881, B:258:0x0886, B:260:0x08d0, B:262:0x08d6, B:268:0x0901, B:270:0x0909, B:271:0x0927, B:273:0x092d, B:274:0x0941, B:276:0x0958, B:278:0x0969, B:280:0x097b, B:282:0x0985, B:283:0x0988, B:285:0x09e3, B:286:0x09f6, B:289:0x09fe, B:292:0x0a1d, B:294:0x0a36, B:296:0x0a4b, B:298:0x0a50, B:300:0x0a54, B:302:0x0a58, B:304:0x0a62, B:305:0x0a68, B:307:0x0a6c, B:309:0x0a72, B:310:0x0a7e, B:311:0x0a87, B:376:0x0cf8, B:313:0x0a92, B:315:0x0aaa, B:320:0x0ad2, B:322:0x0af9, B:323:0x0b01, B:325:0x0b07, B:327:0x0b17, B:334:0x0b41, B:335:0x0b64, B:337:0x0b70, B:339:0x0b86, B:340:0x0bc6, B:346:0x0be0, B:348:0x0beb, B:350:0x0bef, B:352:0x0bf3, B:354:0x0bf7, B:355:0x0c03, B:356:0x0c08, B:358:0x0c0e, B:360:0x0c24, B:361:0x0c29, B:375:0x0cf3, B:362:0x0c67, B:364:0x0c6b, B:368:0x0c7f, B:370:0x0ca1, B:371:0x0ca8, B:374:0x0ce7, B:365:0x0c70, B:332:0x0b2b, B:318:0x0ab6, B:377:0x0d00, B:379:0x0d0e, B:380:0x0d22, B:381:0x0d2a, B:383:0x0d30, B:385:0x0d48, B:387:0x0d5a, B:407:0x0e09, B:409:0x0e0f, B:411:0x0e26, B:414:0x0e2d, B:419:0x0e6e, B:421:0x0e76, B:423:0x0eb4, B:426:0x0ee8, B:427:0x0eec, B:428:0x0ef6, B:430:0x0f37, B:431:0x0f44, B:433:0x0f53, B:436:0x0f6a, B:438:0x0f81, B:425:0x0ec7, B:415:0x0e3c, B:417:0x0e4a, B:418:0x0e55, B:439:0x0f96, B:440:0x0fa9, B:444:0x0fc9, B:443:0x0fb4, B:388:0x0d75, B:390:0x0d7b, B:392:0x0d8b, B:394:0x0d92, B:400:0x0da8, B:402:0x0daf, B:404:0x0dfa, B:406:0x0e01, B:405:0x0dfe, B:401:0x0dac, B:393:0x0d8f, B:263:0x08e6, B:265:0x08ec, B:267:0x08f2, B:247:0x0818, B:243:0x07e7, B:237:0x0790, B:239:0x0796, B:445:0x0fd3), top: B:457:0x0012, inners: #0, #1, #2, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:162:0x055a A[Catch: all -> 0x0117, TryCatch #3 {all -> 0x0117, blocks: (B:3:0x0012, B:5:0x002a, B:8:0x0033, B:9:0x0052, B:12:0x0070, B:15:0x009a, B:17:0x00d7, B:20:0x00f0, B:22:0x00fa, B:208:0x06eb, B:27:0x012f, B:29:0x0141, B:32:0x0151, B:34:0x0157, B:38:0x0161, B:40:0x016e, B:42:0x017c, B:44:0x0182, B:48:0x018d, B:49:0x019b, B:51:0x01ad, B:54:0x01d4, B:56:0x01de, B:58:0x01ee, B:60:0x01fc, B:62:0x020c, B:63:0x0217, B:64:0x021a, B:67:0x0232, B:76:0x0263, B:79:0x0271, B:81:0x027f, B:86:0x02db, B:82:0x02a3, B:84:0x02b3, B:90:0x02ea, B:92:0x0314, B:93:0x033c, B:95:0x0371, B:97:0x0377, B:100:0x0383, B:102:0x03b8, B:103:0x03d5, B:105:0x03df, B:107:0x03ed, B:111:0x0401, B:108:0x03f5, B:114:0x0408, B:117:0x0416, B:118:0x0435, B:120:0x0450, B:121:0x045c, B:124:0x0466, B:130:0x0489, B:127:0x0478, B:133:0x0490, B:135:0x049c, B:137:0x04a8, B:148:0x04f1, B:140:0x04c9, B:143:0x04db, B:145:0x04e1, B:147:0x04eb, B:149:0x050e, B:151:0x051a, B:154:0x052b, B:156:0x053c, B:158:0x0548, B:174:0x05a2, B:176:0x05ac, B:177:0x05b8, B:179:0x05c2, B:181:0x05d2, B:183:0x05dc, B:184:0x05ef, B:186:0x05f5, B:187:0x0610, B:189:0x0616, B:190:0x0634, B:191:0x0643, B:195:0x066e, B:192:0x064b, B:194:0x0659, B:196:0x0676, B:197:0x0695, B:199:0x069b, B:201:0x06ae, B:202:0x06bb, B:203:0x06bf, B:205:0x06c5, B:207:0x06d3, B:162:0x055a, B:164:0x0568, B:167:0x057b, B:169:0x058c, B:171:0x0598, B:211:0x0704, B:213:0x0716, B:215:0x071f, B:226:0x074e, B:216:0x0725, B:218:0x072e, B:220:0x0734, B:223:0x0740, B:225:0x0748, B:227:0x0751, B:228:0x075d, B:231:0x0765, B:233:0x0777, B:234:0x0782, B:236:0x078a, B:240:0x07b9, B:242:0x07d5, B:244:0x07ea, B:246:0x0806, B:248:0x081b, B:249:0x0837, B:251:0x083d, B:253:0x0855, B:254:0x0863, B:256:0x0873, B:257:0x0881, B:258:0x0886, B:260:0x08d0, B:262:0x08d6, B:268:0x0901, B:270:0x0909, B:271:0x0927, B:273:0x092d, B:274:0x0941, B:276:0x0958, B:278:0x0969, B:280:0x097b, B:282:0x0985, B:283:0x0988, B:285:0x09e3, B:286:0x09f6, B:289:0x09fe, B:292:0x0a1d, B:294:0x0a36, B:296:0x0a4b, B:298:0x0a50, B:300:0x0a54, B:302:0x0a58, B:304:0x0a62, B:305:0x0a68, B:307:0x0a6c, B:309:0x0a72, B:310:0x0a7e, B:311:0x0a87, B:376:0x0cf8, B:313:0x0a92, B:315:0x0aaa, B:320:0x0ad2, B:322:0x0af9, B:323:0x0b01, B:325:0x0b07, B:327:0x0b17, B:334:0x0b41, B:335:0x0b64, B:337:0x0b70, B:339:0x0b86, B:340:0x0bc6, B:346:0x0be0, B:348:0x0beb, B:350:0x0bef, B:352:0x0bf3, B:354:0x0bf7, B:355:0x0c03, B:356:0x0c08, B:358:0x0c0e, B:360:0x0c24, B:361:0x0c29, B:375:0x0cf3, B:362:0x0c67, B:364:0x0c6b, B:368:0x0c7f, B:370:0x0ca1, B:371:0x0ca8, B:374:0x0ce7, B:365:0x0c70, B:332:0x0b2b, B:318:0x0ab6, B:377:0x0d00, B:379:0x0d0e, B:380:0x0d22, B:381:0x0d2a, B:383:0x0d30, B:385:0x0d48, B:387:0x0d5a, B:407:0x0e09, B:409:0x0e0f, B:411:0x0e26, B:414:0x0e2d, B:419:0x0e6e, B:421:0x0e76, B:423:0x0eb4, B:426:0x0ee8, B:427:0x0eec, B:428:0x0ef6, B:430:0x0f37, B:431:0x0f44, B:433:0x0f53, B:436:0x0f6a, B:438:0x0f81, B:425:0x0ec7, B:415:0x0e3c, B:417:0x0e4a, B:418:0x0e55, B:439:0x0f96, B:440:0x0fa9, B:444:0x0fc9, B:443:0x0fb4, B:388:0x0d75, B:390:0x0d7b, B:392:0x0d8b, B:394:0x0d92, B:400:0x0da8, B:402:0x0daf, B:404:0x0dfa, B:406:0x0e01, B:405:0x0dfe, B:401:0x0dac, B:393:0x0d8f, B:263:0x08e6, B:265:0x08ec, B:267:0x08f2, B:247:0x0818, B:243:0x07e7, B:237:0x0790, B:239:0x0796, B:445:0x0fd3), top: B:457:0x0012, inners: #0, #1, #2, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:176:0x05ac A[Catch: all -> 0x0117, TryCatch #3 {all -> 0x0117, blocks: (B:3:0x0012, B:5:0x002a, B:8:0x0033, B:9:0x0052, B:12:0x0070, B:15:0x009a, B:17:0x00d7, B:20:0x00f0, B:22:0x00fa, B:208:0x06eb, B:27:0x012f, B:29:0x0141, B:32:0x0151, B:34:0x0157, B:38:0x0161, B:40:0x016e, B:42:0x017c, B:44:0x0182, B:48:0x018d, B:49:0x019b, B:51:0x01ad, B:54:0x01d4, B:56:0x01de, B:58:0x01ee, B:60:0x01fc, B:62:0x020c, B:63:0x0217, B:64:0x021a, B:67:0x0232, B:76:0x0263, B:79:0x0271, B:81:0x027f, B:86:0x02db, B:82:0x02a3, B:84:0x02b3, B:90:0x02ea, B:92:0x0314, B:93:0x033c, B:95:0x0371, B:97:0x0377, B:100:0x0383, B:102:0x03b8, B:103:0x03d5, B:105:0x03df, B:107:0x03ed, B:111:0x0401, B:108:0x03f5, B:114:0x0408, B:117:0x0416, B:118:0x0435, B:120:0x0450, B:121:0x045c, B:124:0x0466, B:130:0x0489, B:127:0x0478, B:133:0x0490, B:135:0x049c, B:137:0x04a8, B:148:0x04f1, B:140:0x04c9, B:143:0x04db, B:145:0x04e1, B:147:0x04eb, B:149:0x050e, B:151:0x051a, B:154:0x052b, B:156:0x053c, B:158:0x0548, B:174:0x05a2, B:176:0x05ac, B:177:0x05b8, B:179:0x05c2, B:181:0x05d2, B:183:0x05dc, B:184:0x05ef, B:186:0x05f5, B:187:0x0610, B:189:0x0616, B:190:0x0634, B:191:0x0643, B:195:0x066e, B:192:0x064b, B:194:0x0659, B:196:0x0676, B:197:0x0695, B:199:0x069b, B:201:0x06ae, B:202:0x06bb, B:203:0x06bf, B:205:0x06c5, B:207:0x06d3, B:162:0x055a, B:164:0x0568, B:167:0x057b, B:169:0x058c, B:171:0x0598, B:211:0x0704, B:213:0x0716, B:215:0x071f, B:226:0x074e, B:216:0x0725, B:218:0x072e, B:220:0x0734, B:223:0x0740, B:225:0x0748, B:227:0x0751, B:228:0x075d, B:231:0x0765, B:233:0x0777, B:234:0x0782, B:236:0x078a, B:240:0x07b9, B:242:0x07d5, B:244:0x07ea, B:246:0x0806, B:248:0x081b, B:249:0x0837, B:251:0x083d, B:253:0x0855, B:254:0x0863, B:256:0x0873, B:257:0x0881, B:258:0x0886, B:260:0x08d0, B:262:0x08d6, B:268:0x0901, B:270:0x0909, B:271:0x0927, B:273:0x092d, B:274:0x0941, B:276:0x0958, B:278:0x0969, B:280:0x097b, B:282:0x0985, B:283:0x0988, B:285:0x09e3, B:286:0x09f6, B:289:0x09fe, B:292:0x0a1d, B:294:0x0a36, B:296:0x0a4b, B:298:0x0a50, B:300:0x0a54, B:302:0x0a58, B:304:0x0a62, B:305:0x0a68, B:307:0x0a6c, B:309:0x0a72, B:310:0x0a7e, B:311:0x0a87, B:376:0x0cf8, B:313:0x0a92, B:315:0x0aaa, B:320:0x0ad2, B:322:0x0af9, B:323:0x0b01, B:325:0x0b07, B:327:0x0b17, B:334:0x0b41, B:335:0x0b64, B:337:0x0b70, B:339:0x0b86, B:340:0x0bc6, B:346:0x0be0, B:348:0x0beb, B:350:0x0bef, B:352:0x0bf3, B:354:0x0bf7, B:355:0x0c03, B:356:0x0c08, B:358:0x0c0e, B:360:0x0c24, B:361:0x0c29, B:375:0x0cf3, B:362:0x0c67, B:364:0x0c6b, B:368:0x0c7f, B:370:0x0ca1, B:371:0x0ca8, B:374:0x0ce7, B:365:0x0c70, B:332:0x0b2b, B:318:0x0ab6, B:377:0x0d00, B:379:0x0d0e, B:380:0x0d22, B:381:0x0d2a, B:383:0x0d30, B:385:0x0d48, B:387:0x0d5a, B:407:0x0e09, B:409:0x0e0f, B:411:0x0e26, B:414:0x0e2d, B:419:0x0e6e, B:421:0x0e76, B:423:0x0eb4, B:426:0x0ee8, B:427:0x0eec, B:428:0x0ef6, B:430:0x0f37, B:431:0x0f44, B:433:0x0f53, B:436:0x0f6a, B:438:0x0f81, B:425:0x0ec7, B:415:0x0e3c, B:417:0x0e4a, B:418:0x0e55, B:439:0x0f96, B:440:0x0fa9, B:444:0x0fc9, B:443:0x0fb4, B:388:0x0d75, B:390:0x0d7b, B:392:0x0d8b, B:394:0x0d92, B:400:0x0da8, B:402:0x0daf, B:404:0x0dfa, B:406:0x0e01, B:405:0x0dfe, B:401:0x0dac, B:393:0x0d8f, B:263:0x08e6, B:265:0x08ec, B:267:0x08f2, B:247:0x0818, B:243:0x07e7, B:237:0x0790, B:239:0x0796, B:445:0x0fd3), top: B:457:0x0012, inners: #0, #1, #2, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:206:0x06cf  */
    /* JADX WARN: Removed duplicated region for block: B:216:0x0725 A[Catch: all -> 0x0117, TryCatch #3 {all -> 0x0117, blocks: (B:3:0x0012, B:5:0x002a, B:8:0x0033, B:9:0x0052, B:12:0x0070, B:15:0x009a, B:17:0x00d7, B:20:0x00f0, B:22:0x00fa, B:208:0x06eb, B:27:0x012f, B:29:0x0141, B:32:0x0151, B:34:0x0157, B:38:0x0161, B:40:0x016e, B:42:0x017c, B:44:0x0182, B:48:0x018d, B:49:0x019b, B:51:0x01ad, B:54:0x01d4, B:56:0x01de, B:58:0x01ee, B:60:0x01fc, B:62:0x020c, B:63:0x0217, B:64:0x021a, B:67:0x0232, B:76:0x0263, B:79:0x0271, B:81:0x027f, B:86:0x02db, B:82:0x02a3, B:84:0x02b3, B:90:0x02ea, B:92:0x0314, B:93:0x033c, B:95:0x0371, B:97:0x0377, B:100:0x0383, B:102:0x03b8, B:103:0x03d5, B:105:0x03df, B:107:0x03ed, B:111:0x0401, B:108:0x03f5, B:114:0x0408, B:117:0x0416, B:118:0x0435, B:120:0x0450, B:121:0x045c, B:124:0x0466, B:130:0x0489, B:127:0x0478, B:133:0x0490, B:135:0x049c, B:137:0x04a8, B:148:0x04f1, B:140:0x04c9, B:143:0x04db, B:145:0x04e1, B:147:0x04eb, B:149:0x050e, B:151:0x051a, B:154:0x052b, B:156:0x053c, B:158:0x0548, B:174:0x05a2, B:176:0x05ac, B:177:0x05b8, B:179:0x05c2, B:181:0x05d2, B:183:0x05dc, B:184:0x05ef, B:186:0x05f5, B:187:0x0610, B:189:0x0616, B:190:0x0634, B:191:0x0643, B:195:0x066e, B:192:0x064b, B:194:0x0659, B:196:0x0676, B:197:0x0695, B:199:0x069b, B:201:0x06ae, B:202:0x06bb, B:203:0x06bf, B:205:0x06c5, B:207:0x06d3, B:162:0x055a, B:164:0x0568, B:167:0x057b, B:169:0x058c, B:171:0x0598, B:211:0x0704, B:213:0x0716, B:215:0x071f, B:226:0x074e, B:216:0x0725, B:218:0x072e, B:220:0x0734, B:223:0x0740, B:225:0x0748, B:227:0x0751, B:228:0x075d, B:231:0x0765, B:233:0x0777, B:234:0x0782, B:236:0x078a, B:240:0x07b9, B:242:0x07d5, B:244:0x07ea, B:246:0x0806, B:248:0x081b, B:249:0x0837, B:251:0x083d, B:253:0x0855, B:254:0x0863, B:256:0x0873, B:257:0x0881, B:258:0x0886, B:260:0x08d0, B:262:0x08d6, B:268:0x0901, B:270:0x0909, B:271:0x0927, B:273:0x092d, B:274:0x0941, B:276:0x0958, B:278:0x0969, B:280:0x097b, B:282:0x0985, B:283:0x0988, B:285:0x09e3, B:286:0x09f6, B:289:0x09fe, B:292:0x0a1d, B:294:0x0a36, B:296:0x0a4b, B:298:0x0a50, B:300:0x0a54, B:302:0x0a58, B:304:0x0a62, B:305:0x0a68, B:307:0x0a6c, B:309:0x0a72, B:310:0x0a7e, B:311:0x0a87, B:376:0x0cf8, B:313:0x0a92, B:315:0x0aaa, B:320:0x0ad2, B:322:0x0af9, B:323:0x0b01, B:325:0x0b07, B:327:0x0b17, B:334:0x0b41, B:335:0x0b64, B:337:0x0b70, B:339:0x0b86, B:340:0x0bc6, B:346:0x0be0, B:348:0x0beb, B:350:0x0bef, B:352:0x0bf3, B:354:0x0bf7, B:355:0x0c03, B:356:0x0c08, B:358:0x0c0e, B:360:0x0c24, B:361:0x0c29, B:375:0x0cf3, B:362:0x0c67, B:364:0x0c6b, B:368:0x0c7f, B:370:0x0ca1, B:371:0x0ca8, B:374:0x0ce7, B:365:0x0c70, B:332:0x0b2b, B:318:0x0ab6, B:377:0x0d00, B:379:0x0d0e, B:380:0x0d22, B:381:0x0d2a, B:383:0x0d30, B:385:0x0d48, B:387:0x0d5a, B:407:0x0e09, B:409:0x0e0f, B:411:0x0e26, B:414:0x0e2d, B:419:0x0e6e, B:421:0x0e76, B:423:0x0eb4, B:426:0x0ee8, B:427:0x0eec, B:428:0x0ef6, B:430:0x0f37, B:431:0x0f44, B:433:0x0f53, B:436:0x0f6a, B:438:0x0f81, B:425:0x0ec7, B:415:0x0e3c, B:417:0x0e4a, B:418:0x0e55, B:439:0x0f96, B:440:0x0fa9, B:444:0x0fc9, B:443:0x0fb4, B:388:0x0d75, B:390:0x0d7b, B:392:0x0d8b, B:394:0x0d92, B:400:0x0da8, B:402:0x0daf, B:404:0x0dfa, B:406:0x0e01, B:405:0x0dfe, B:401:0x0dac, B:393:0x0d8f, B:263:0x08e6, B:265:0x08ec, B:267:0x08f2, B:247:0x0818, B:243:0x07e7, B:237:0x0790, B:239:0x0796, B:445:0x0fd3), top: B:457:0x0012, inners: #0, #1, #2, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:334:0x0b41 A[Catch: all -> 0x0117, TryCatch #3 {all -> 0x0117, blocks: (B:3:0x0012, B:5:0x002a, B:8:0x0033, B:9:0x0052, B:12:0x0070, B:15:0x009a, B:17:0x00d7, B:20:0x00f0, B:22:0x00fa, B:208:0x06eb, B:27:0x012f, B:29:0x0141, B:32:0x0151, B:34:0x0157, B:38:0x0161, B:40:0x016e, B:42:0x017c, B:44:0x0182, B:48:0x018d, B:49:0x019b, B:51:0x01ad, B:54:0x01d4, B:56:0x01de, B:58:0x01ee, B:60:0x01fc, B:62:0x020c, B:63:0x0217, B:64:0x021a, B:67:0x0232, B:76:0x0263, B:79:0x0271, B:81:0x027f, B:86:0x02db, B:82:0x02a3, B:84:0x02b3, B:90:0x02ea, B:92:0x0314, B:93:0x033c, B:95:0x0371, B:97:0x0377, B:100:0x0383, B:102:0x03b8, B:103:0x03d5, B:105:0x03df, B:107:0x03ed, B:111:0x0401, B:108:0x03f5, B:114:0x0408, B:117:0x0416, B:118:0x0435, B:120:0x0450, B:121:0x045c, B:124:0x0466, B:130:0x0489, B:127:0x0478, B:133:0x0490, B:135:0x049c, B:137:0x04a8, B:148:0x04f1, B:140:0x04c9, B:143:0x04db, B:145:0x04e1, B:147:0x04eb, B:149:0x050e, B:151:0x051a, B:154:0x052b, B:156:0x053c, B:158:0x0548, B:174:0x05a2, B:176:0x05ac, B:177:0x05b8, B:179:0x05c2, B:181:0x05d2, B:183:0x05dc, B:184:0x05ef, B:186:0x05f5, B:187:0x0610, B:189:0x0616, B:190:0x0634, B:191:0x0643, B:195:0x066e, B:192:0x064b, B:194:0x0659, B:196:0x0676, B:197:0x0695, B:199:0x069b, B:201:0x06ae, B:202:0x06bb, B:203:0x06bf, B:205:0x06c5, B:207:0x06d3, B:162:0x055a, B:164:0x0568, B:167:0x057b, B:169:0x058c, B:171:0x0598, B:211:0x0704, B:213:0x0716, B:215:0x071f, B:226:0x074e, B:216:0x0725, B:218:0x072e, B:220:0x0734, B:223:0x0740, B:225:0x0748, B:227:0x0751, B:228:0x075d, B:231:0x0765, B:233:0x0777, B:234:0x0782, B:236:0x078a, B:240:0x07b9, B:242:0x07d5, B:244:0x07ea, B:246:0x0806, B:248:0x081b, B:249:0x0837, B:251:0x083d, B:253:0x0855, B:254:0x0863, B:256:0x0873, B:257:0x0881, B:258:0x0886, B:260:0x08d0, B:262:0x08d6, B:268:0x0901, B:270:0x0909, B:271:0x0927, B:273:0x092d, B:274:0x0941, B:276:0x0958, B:278:0x0969, B:280:0x097b, B:282:0x0985, B:283:0x0988, B:285:0x09e3, B:286:0x09f6, B:289:0x09fe, B:292:0x0a1d, B:294:0x0a36, B:296:0x0a4b, B:298:0x0a50, B:300:0x0a54, B:302:0x0a58, B:304:0x0a62, B:305:0x0a68, B:307:0x0a6c, B:309:0x0a72, B:310:0x0a7e, B:311:0x0a87, B:376:0x0cf8, B:313:0x0a92, B:315:0x0aaa, B:320:0x0ad2, B:322:0x0af9, B:323:0x0b01, B:325:0x0b07, B:327:0x0b17, B:334:0x0b41, B:335:0x0b64, B:337:0x0b70, B:339:0x0b86, B:340:0x0bc6, B:346:0x0be0, B:348:0x0beb, B:350:0x0bef, B:352:0x0bf3, B:354:0x0bf7, B:355:0x0c03, B:356:0x0c08, B:358:0x0c0e, B:360:0x0c24, B:361:0x0c29, B:375:0x0cf3, B:362:0x0c67, B:364:0x0c6b, B:368:0x0c7f, B:370:0x0ca1, B:371:0x0ca8, B:374:0x0ce7, B:365:0x0c70, B:332:0x0b2b, B:318:0x0ab6, B:377:0x0d00, B:379:0x0d0e, B:380:0x0d22, B:381:0x0d2a, B:383:0x0d30, B:385:0x0d48, B:387:0x0d5a, B:407:0x0e09, B:409:0x0e0f, B:411:0x0e26, B:414:0x0e2d, B:419:0x0e6e, B:421:0x0e76, B:423:0x0eb4, B:426:0x0ee8, B:427:0x0eec, B:428:0x0ef6, B:430:0x0f37, B:431:0x0f44, B:433:0x0f53, B:436:0x0f6a, B:438:0x0f81, B:425:0x0ec7, B:415:0x0e3c, B:417:0x0e4a, B:418:0x0e55, B:439:0x0f96, B:440:0x0fa9, B:444:0x0fc9, B:443:0x0fb4, B:388:0x0d75, B:390:0x0d7b, B:392:0x0d8b, B:394:0x0d92, B:400:0x0da8, B:402:0x0daf, B:404:0x0dfa, B:406:0x0e01, B:405:0x0dfe, B:401:0x0dac, B:393:0x0d8f, B:263:0x08e6, B:265:0x08ec, B:267:0x08f2, B:247:0x0818, B:243:0x07e7, B:237:0x0790, B:239:0x0796, B:445:0x0fd3), top: B:457:0x0012, inners: #0, #1, #2, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:335:0x0b64 A[Catch: all -> 0x0117, TryCatch #3 {all -> 0x0117, blocks: (B:3:0x0012, B:5:0x002a, B:8:0x0033, B:9:0x0052, B:12:0x0070, B:15:0x009a, B:17:0x00d7, B:20:0x00f0, B:22:0x00fa, B:208:0x06eb, B:27:0x012f, B:29:0x0141, B:32:0x0151, B:34:0x0157, B:38:0x0161, B:40:0x016e, B:42:0x017c, B:44:0x0182, B:48:0x018d, B:49:0x019b, B:51:0x01ad, B:54:0x01d4, B:56:0x01de, B:58:0x01ee, B:60:0x01fc, B:62:0x020c, B:63:0x0217, B:64:0x021a, B:67:0x0232, B:76:0x0263, B:79:0x0271, B:81:0x027f, B:86:0x02db, B:82:0x02a3, B:84:0x02b3, B:90:0x02ea, B:92:0x0314, B:93:0x033c, B:95:0x0371, B:97:0x0377, B:100:0x0383, B:102:0x03b8, B:103:0x03d5, B:105:0x03df, B:107:0x03ed, B:111:0x0401, B:108:0x03f5, B:114:0x0408, B:117:0x0416, B:118:0x0435, B:120:0x0450, B:121:0x045c, B:124:0x0466, B:130:0x0489, B:127:0x0478, B:133:0x0490, B:135:0x049c, B:137:0x04a8, B:148:0x04f1, B:140:0x04c9, B:143:0x04db, B:145:0x04e1, B:147:0x04eb, B:149:0x050e, B:151:0x051a, B:154:0x052b, B:156:0x053c, B:158:0x0548, B:174:0x05a2, B:176:0x05ac, B:177:0x05b8, B:179:0x05c2, B:181:0x05d2, B:183:0x05dc, B:184:0x05ef, B:186:0x05f5, B:187:0x0610, B:189:0x0616, B:190:0x0634, B:191:0x0643, B:195:0x066e, B:192:0x064b, B:194:0x0659, B:196:0x0676, B:197:0x0695, B:199:0x069b, B:201:0x06ae, B:202:0x06bb, B:203:0x06bf, B:205:0x06c5, B:207:0x06d3, B:162:0x055a, B:164:0x0568, B:167:0x057b, B:169:0x058c, B:171:0x0598, B:211:0x0704, B:213:0x0716, B:215:0x071f, B:226:0x074e, B:216:0x0725, B:218:0x072e, B:220:0x0734, B:223:0x0740, B:225:0x0748, B:227:0x0751, B:228:0x075d, B:231:0x0765, B:233:0x0777, B:234:0x0782, B:236:0x078a, B:240:0x07b9, B:242:0x07d5, B:244:0x07ea, B:246:0x0806, B:248:0x081b, B:249:0x0837, B:251:0x083d, B:253:0x0855, B:254:0x0863, B:256:0x0873, B:257:0x0881, B:258:0x0886, B:260:0x08d0, B:262:0x08d6, B:268:0x0901, B:270:0x0909, B:271:0x0927, B:273:0x092d, B:274:0x0941, B:276:0x0958, B:278:0x0969, B:280:0x097b, B:282:0x0985, B:283:0x0988, B:285:0x09e3, B:286:0x09f6, B:289:0x09fe, B:292:0x0a1d, B:294:0x0a36, B:296:0x0a4b, B:298:0x0a50, B:300:0x0a54, B:302:0x0a58, B:304:0x0a62, B:305:0x0a68, B:307:0x0a6c, B:309:0x0a72, B:310:0x0a7e, B:311:0x0a87, B:376:0x0cf8, B:313:0x0a92, B:315:0x0aaa, B:320:0x0ad2, B:322:0x0af9, B:323:0x0b01, B:325:0x0b07, B:327:0x0b17, B:334:0x0b41, B:335:0x0b64, B:337:0x0b70, B:339:0x0b86, B:340:0x0bc6, B:346:0x0be0, B:348:0x0beb, B:350:0x0bef, B:352:0x0bf3, B:354:0x0bf7, B:355:0x0c03, B:356:0x0c08, B:358:0x0c0e, B:360:0x0c24, B:361:0x0c29, B:375:0x0cf3, B:362:0x0c67, B:364:0x0c6b, B:368:0x0c7f, B:370:0x0ca1, B:371:0x0ca8, B:374:0x0ce7, B:365:0x0c70, B:332:0x0b2b, B:318:0x0ab6, B:377:0x0d00, B:379:0x0d0e, B:380:0x0d22, B:381:0x0d2a, B:383:0x0d30, B:385:0x0d48, B:387:0x0d5a, B:407:0x0e09, B:409:0x0e0f, B:411:0x0e26, B:414:0x0e2d, B:419:0x0e6e, B:421:0x0e76, B:423:0x0eb4, B:426:0x0ee8, B:427:0x0eec, B:428:0x0ef6, B:430:0x0f37, B:431:0x0f44, B:433:0x0f53, B:436:0x0f6a, B:438:0x0f81, B:425:0x0ec7, B:415:0x0e3c, B:417:0x0e4a, B:418:0x0e55, B:439:0x0f96, B:440:0x0fa9, B:444:0x0fc9, B:443:0x0fb4, B:388:0x0d75, B:390:0x0d7b, B:392:0x0d8b, B:394:0x0d92, B:400:0x0da8, B:402:0x0daf, B:404:0x0dfa, B:406:0x0e01, B:405:0x0dfe, B:401:0x0dac, B:393:0x0d8f, B:263:0x08e6, B:265:0x08ec, B:267:0x08f2, B:247:0x0818, B:243:0x07e7, B:237:0x0790, B:239:0x0796, B:445:0x0fd3), top: B:457:0x0012, inners: #0, #1, #2, #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:37:0x015e  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x018b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean G(long r48, java.lang.String r50) throws java.lang.NumberFormatException {
        /*
            Method dump skipped, instructions count: 4075
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.G(long, java.lang.String):boolean");
    }

    public final boolean H() {
        Z.l(this);
        C3874j c3874j = this.c;
        L(c3874j);
        if (c3874j.J0("select count(1) > 0 from raw_events", null) != 0) {
            return true;
        }
        C3874j c3874j2 = this.c;
        L(c3874j2);
        return !TextUtils.isEmpty(c3874j2.W());
    }

    public final boolean I(String str, String str2) {
        C3874j c3874j = this.c;
        L(c3874j);
        C3882n c3882nU0 = c3874j.u0("events", str, str2);
        return c3882nU0 == null || c3882nU0.c < 1;
    }

    public final boolean J(com.google.android.gms.internal.measurement.T0 t0, com.google.android.gms.internal.measurement.T0 t02) {
        com.google.android.gms.common.internal.u.b("_e".equals(t0.o()));
        a();
        com.google.android.gms.internal.measurement.X0 x0B0 = M.b0((com.google.android.gms.internal.measurement.U0) t0.f(), "_sc");
        String strT = x0B0 == null ? null : x0B0.t();
        a();
        com.google.android.gms.internal.measurement.X0 x0B02 = M.b0((com.google.android.gms.internal.measurement.U0) t02.f(), "_pc");
        String strT2 = x0B02 != null ? x0B02.t() : null;
        if (strT2 == null || !strT2.equals(strT)) {
            return false;
        }
        com.google.android.gms.common.internal.u.b("_e".equals(t0.o()));
        a();
        com.google.android.gms.internal.measurement.X0 x0B03 = M.b0((com.google.android.gms.internal.measurement.U0) t0.f(), "_et");
        if (x0B03 == null || !x0B03.H() || x0B03.q() <= 0) {
            return true;
        }
        long jQ = x0B03.q();
        a();
        com.google.android.gms.internal.measurement.X0 x0B04 = M.b0((com.google.android.gms.internal.measurement.U0) t02.f(), "_et");
        if (x0B04 != null && x0B04.q() > 0) {
            jQ += x0B04.q();
        }
        a();
        M.Z(t02, "_et", Long.valueOf(jQ));
        a();
        M.Z(t0, "_fr", 1L);
        return true;
    }

    public final void N(F f, C2969b1 c2969b1) {
        i().S();
        k();
        com.google.android.gms.internal.measurement.K0 k0X = com.google.android.gms.internal.measurement.L0.x();
        Y y = f.a;
        X x = y.j;
        Y.k(x);
        x.S();
        byte[] bArr = f.I;
        if (bArr != null) {
            try {
                k0X = (com.google.android.gms.internal.measurement.K0) M.y0(k0X, bArr);
            } catch (zzmm unused) {
                c().j.g("Failed to parse locally stored ad campaign info. appId", I.a0(f.c()));
            }
        }
        for (com.google.android.gms.internal.measurement.U0 u0 : c2969b1.A()) {
            if (u0.t().equals("_cmp")) {
                Serializable serializableC0 = M.c0(u0, "gclid");
                if (serializableC0 == null) {
                    serializableC0 = "";
                }
                String str = (String) serializableC0;
                Serializable serializableC02 = M.c0(u0, "gbraid");
                if (serializableC02 == null) {
                    serializableC02 = "";
                }
                String str2 = (String) serializableC02;
                Object objC0 = M.c0(u0, "gad_source");
                String str3 = (String) (objC0 != null ? objC0 : "");
                if (!str.isEmpty() || !str2.isEmpty()) {
                    Object objC02 = M.c0(u0, "click_timestamp");
                    long jLongValue = ((Long) (objC02 != null ? objC02 : 0L)).longValue();
                    if (jLongValue <= 0) {
                        jLongValue = u0.q();
                    }
                    if ("referrer API v2".equals(M.c0(u0, "_cis"))) {
                        if (jLongValue > ((com.google.android.gms.internal.measurement.L0) k0X.b).w()) {
                            if (str.isEmpty()) {
                                k0X.h();
                                com.google.android.gms.internal.measurement.L0.K((com.google.android.gms.internal.measurement.L0) k0X.b);
                            } else {
                                k0X.h();
                                com.google.android.gms.internal.measurement.L0.S((com.google.android.gms.internal.measurement.L0) k0X.b, str);
                            }
                            if (str2.isEmpty()) {
                                k0X.h();
                                com.google.android.gms.internal.measurement.L0.J((com.google.android.gms.internal.measurement.L0) k0X.b);
                            } else {
                                k0X.h();
                                com.google.android.gms.internal.measurement.L0.R((com.google.android.gms.internal.measurement.L0) k0X.b, str2);
                            }
                            if (str3.isEmpty()) {
                                k0X.h();
                                com.google.android.gms.internal.measurement.L0.I((com.google.android.gms.internal.measurement.L0) k0X.b);
                            } else {
                                k0X.h();
                                com.google.android.gms.internal.measurement.L0.Q((com.google.android.gms.internal.measurement.L0) k0X.b, str3);
                            }
                            k0X.h();
                            com.google.android.gms.internal.measurement.L0.P((com.google.android.gms.internal.measurement.L0) k0X.b, jLongValue);
                        }
                    } else if (jLongValue > ((com.google.android.gms.internal.measurement.L0) k0X.b).v()) {
                        if (str.isEmpty()) {
                            k0X.h();
                            com.google.android.gms.internal.measurement.L0.H((com.google.android.gms.internal.measurement.L0) k0X.b);
                        } else {
                            k0X.h();
                            com.google.android.gms.internal.measurement.L0.N((com.google.android.gms.internal.measurement.L0) k0X.b, str);
                        }
                        if (str2.isEmpty()) {
                            k0X.h();
                            com.google.android.gms.internal.measurement.L0.G((com.google.android.gms.internal.measurement.L0) k0X.b);
                        } else {
                            k0X.h();
                            com.google.android.gms.internal.measurement.L0.M((com.google.android.gms.internal.measurement.L0) k0X.b, str2);
                        }
                        if (str3.isEmpty()) {
                            k0X.h();
                            com.google.android.gms.internal.measurement.L0.F((com.google.android.gms.internal.measurement.L0) k0X.b);
                        } else {
                            k0X.h();
                            com.google.android.gms.internal.measurement.L0.L((com.google.android.gms.internal.measurement.L0) k0X.b, str3);
                        }
                        k0X.h();
                        com.google.android.gms.internal.measurement.L0.O((com.google.android.gms.internal.measurement.L0) k0X.b, jLongValue);
                    }
                }
            }
        }
        if (!((com.google.android.gms.internal.measurement.L0) k0X.f()).equals(com.google.android.gms.internal.measurement.L0.y())) {
            com.google.android.gms.internal.measurement.L0 l0 = (com.google.android.gms.internal.measurement.L0) k0X.f();
            c2969b1.h();
            C2974c1.H0((C2974c1) c2969b1.b, l0);
        }
        byte[] bArrC = ((com.google.android.gms.internal.measurement.L0) k0X.f()).c();
        X x2 = y.j;
        Y.k(x2);
        x2.S();
        f.R |= f.I != bArrC;
        f.I = bArrC;
        if (f.s()) {
            C3874j c3874j = this.c;
            L(c3874j);
            c3874j.o0(f, false);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:131:0x0323  */
    /* JADX WARN: Removed duplicated region for block: B:152:0x03c9 A[Catch: all -> 0x00cd, TryCatch #3 {all -> 0x00cd, blocks: (B:24:0x00ac, B:26:0x00bd, B:34:0x00d4, B:38:0x00e4, B:40:0x00f1, B:46:0x0106, B:48:0x0113, B:50:0x011c, B:53:0x0123, B:56:0x013e, B:60:0x0156, B:63:0x0178, B:66:0x0184, B:68:0x018a, B:71:0x019a, B:100:0x0258, B:102:0x0282, B:103:0x0285, B:105:0x02a2, B:146:0x0362, B:147:0x0365, B:155:0x03ea, B:108:0x02b7, B:113:0x02d4, B:115:0x02dc, B:117:0x02e2, B:121:0x02f5, B:125:0x0308, B:129:0x0314, B:132:0x0326, B:137:0x0343, B:139:0x034b, B:141:0x0353, B:143:0x0359, B:135:0x0331, B:123:0x0300, B:111:0x02c2, B:72:0x01a8, B:74:0x01d0, B:75:0x01dc, B:77:0x01e3, B:79:0x01e9, B:81:0x01f3, B:83:0x01f9, B:85:0x01ff, B:87:0x0205, B:88:0x020a, B:94:0x0223, B:96:0x0227, B:97:0x0236, B:98:0x0241, B:99:0x024c, B:148:0x037c, B:150:0x03b0, B:151:0x03b3, B:152:0x03c9, B:154:0x03d0, B:54:0x0130, B:49:0x0119, B:42:0x00fb, B:45:0x0103), top: B:166:0x00ac, inners: #0, #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0113 A[Catch: all -> 0x00cd, TryCatch #3 {all -> 0x00cd, blocks: (B:24:0x00ac, B:26:0x00bd, B:34:0x00d4, B:38:0x00e4, B:40:0x00f1, B:46:0x0106, B:48:0x0113, B:50:0x011c, B:53:0x0123, B:56:0x013e, B:60:0x0156, B:63:0x0178, B:66:0x0184, B:68:0x018a, B:71:0x019a, B:100:0x0258, B:102:0x0282, B:103:0x0285, B:105:0x02a2, B:146:0x0362, B:147:0x0365, B:155:0x03ea, B:108:0x02b7, B:113:0x02d4, B:115:0x02dc, B:117:0x02e2, B:121:0x02f5, B:125:0x0308, B:129:0x0314, B:132:0x0326, B:137:0x0343, B:139:0x034b, B:141:0x0353, B:143:0x0359, B:135:0x0331, B:123:0x0300, B:111:0x02c2, B:72:0x01a8, B:74:0x01d0, B:75:0x01dc, B:77:0x01e3, B:79:0x01e9, B:81:0x01f3, B:83:0x01f9, B:85:0x01ff, B:87:0x0205, B:88:0x020a, B:94:0x0223, B:96:0x0227, B:97:0x0236, B:98:0x0241, B:99:0x024c, B:148:0x037c, B:150:0x03b0, B:151:0x03b3, B:152:0x03c9, B:154:0x03d0, B:54:0x0130, B:49:0x0119, B:42:0x00fb, B:45:0x0103), top: B:166:0x00ac, inners: #0, #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:49:0x0119 A[Catch: all -> 0x00cd, TryCatch #3 {all -> 0x00cd, blocks: (B:24:0x00ac, B:26:0x00bd, B:34:0x00d4, B:38:0x00e4, B:40:0x00f1, B:46:0x0106, B:48:0x0113, B:50:0x011c, B:53:0x0123, B:56:0x013e, B:60:0x0156, B:63:0x0178, B:66:0x0184, B:68:0x018a, B:71:0x019a, B:100:0x0258, B:102:0x0282, B:103:0x0285, B:105:0x02a2, B:146:0x0362, B:147:0x0365, B:155:0x03ea, B:108:0x02b7, B:113:0x02d4, B:115:0x02dc, B:117:0x02e2, B:121:0x02f5, B:125:0x0308, B:129:0x0314, B:132:0x0326, B:137:0x0343, B:139:0x034b, B:141:0x0353, B:143:0x0359, B:135:0x0331, B:123:0x0300, B:111:0x02c2, B:72:0x01a8, B:74:0x01d0, B:75:0x01dc, B:77:0x01e3, B:79:0x01e9, B:81:0x01f3, B:83:0x01f9, B:85:0x01ff, B:87:0x0205, B:88:0x020a, B:94:0x0223, B:96:0x0227, B:97:0x0236, B:98:0x0241, B:99:0x024c, B:148:0x037c, B:150:0x03b0, B:151:0x03b3, B:152:0x03c9, B:154:0x03d0, B:54:0x0130, B:49:0x0119, B:42:0x00fb, B:45:0x0103), top: B:166:0x00ac, inners: #0, #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:53:0x0123 A[Catch: all -> 0x00cd, TRY_ENTER, TryCatch #3 {all -> 0x00cd, blocks: (B:24:0x00ac, B:26:0x00bd, B:34:0x00d4, B:38:0x00e4, B:40:0x00f1, B:46:0x0106, B:48:0x0113, B:50:0x011c, B:53:0x0123, B:56:0x013e, B:60:0x0156, B:63:0x0178, B:66:0x0184, B:68:0x018a, B:71:0x019a, B:100:0x0258, B:102:0x0282, B:103:0x0285, B:105:0x02a2, B:146:0x0362, B:147:0x0365, B:155:0x03ea, B:108:0x02b7, B:113:0x02d4, B:115:0x02dc, B:117:0x02e2, B:121:0x02f5, B:125:0x0308, B:129:0x0314, B:132:0x0326, B:137:0x0343, B:139:0x034b, B:141:0x0353, B:143:0x0359, B:135:0x0331, B:123:0x0300, B:111:0x02c2, B:72:0x01a8, B:74:0x01d0, B:75:0x01dc, B:77:0x01e3, B:79:0x01e9, B:81:0x01f3, B:83:0x01f9, B:85:0x01ff, B:87:0x0205, B:88:0x020a, B:94:0x0223, B:96:0x0227, B:97:0x0236, B:98:0x0241, B:99:0x024c, B:148:0x037c, B:150:0x03b0, B:151:0x03b3, B:152:0x03c9, B:154:0x03d0, B:54:0x0130, B:49:0x0119, B:42:0x00fb, B:45:0x0103), top: B:166:0x00ac, inners: #0, #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0130 A[Catch: all -> 0x00cd, TryCatch #3 {all -> 0x00cd, blocks: (B:24:0x00ac, B:26:0x00bd, B:34:0x00d4, B:38:0x00e4, B:40:0x00f1, B:46:0x0106, B:48:0x0113, B:50:0x011c, B:53:0x0123, B:56:0x013e, B:60:0x0156, B:63:0x0178, B:66:0x0184, B:68:0x018a, B:71:0x019a, B:100:0x0258, B:102:0x0282, B:103:0x0285, B:105:0x02a2, B:146:0x0362, B:147:0x0365, B:155:0x03ea, B:108:0x02b7, B:113:0x02d4, B:115:0x02dc, B:117:0x02e2, B:121:0x02f5, B:125:0x0308, B:129:0x0314, B:132:0x0326, B:137:0x0343, B:139:0x034b, B:141:0x0353, B:143:0x0359, B:135:0x0331, B:123:0x0300, B:111:0x02c2, B:72:0x01a8, B:74:0x01d0, B:75:0x01dc, B:77:0x01e3, B:79:0x01e9, B:81:0x01f3, B:83:0x01f9, B:85:0x01ff, B:87:0x0205, B:88:0x020a, B:94:0x0223, B:96:0x0227, B:97:0x0236, B:98:0x0241, B:99:0x024c, B:148:0x037c, B:150:0x03b0, B:151:0x03b3, B:152:0x03c9, B:154:0x03d0, B:54:0x0130, B:49:0x0119, B:42:0x00fb, B:45:0x0103), top: B:166:0x00ac, inners: #0, #1, #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:56:0x013e A[Catch: all -> 0x00cd, TRY_LEAVE, TryCatch #3 {all -> 0x00cd, blocks: (B:24:0x00ac, B:26:0x00bd, B:34:0x00d4, B:38:0x00e4, B:40:0x00f1, B:46:0x0106, B:48:0x0113, B:50:0x011c, B:53:0x0123, B:56:0x013e, B:60:0x0156, B:63:0x0178, B:66:0x0184, B:68:0x018a, B:71:0x019a, B:100:0x0258, B:102:0x0282, B:103:0x0285, B:105:0x02a2, B:146:0x0362, B:147:0x0365, B:155:0x03ea, B:108:0x02b7, B:113:0x02d4, B:115:0x02dc, B:117:0x02e2, B:121:0x02f5, B:125:0x0308, B:129:0x0314, B:132:0x0326, B:137:0x0343, B:139:0x034b, B:141:0x0353, B:143:0x0359, B:135:0x0331, B:123:0x0300, B:111:0x02c2, B:72:0x01a8, B:74:0x01d0, B:75:0x01dc, B:77:0x01e3, B:79:0x01e9, B:81:0x01f3, B:83:0x01f9, B:85:0x01ff, B:87:0x0205, B:88:0x020a, B:94:0x0223, B:96:0x0227, B:97:0x0236, B:98:0x0241, B:99:0x024c, B:148:0x037c, B:150:0x03b0, B:151:0x03b3, B:152:0x03c9, B:154:0x03d0, B:54:0x0130, B:49:0x0119, B:42:0x00fb, B:45:0x0103), top: B:166:0x00ac, inners: #0, #1, #2 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void O(com.google.android.gms.measurement.internal.zzr r31) {
        /*
            Method dump skipped, instructions count: 1028
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.O(com.google.android.gms.measurement.internal.zzr):void");
    }

    public final void P(zzai zzaiVar, zzr zzrVar) {
        com.google.android.gms.common.internal.u.e(zzaiVar.a);
        com.google.android.gms.common.internal.u.h(zzaiVar.c);
        com.google.android.gms.common.internal.u.e(zzaiVar.c.b);
        i().S();
        k();
        if (K(zzrVar)) {
            if (!zzrVar.h) {
                f0(zzrVar);
                return;
            }
            C3874j c3874j = this.c;
            L(c3874j);
            c3874j.d0();
            try {
                f0(zzrVar);
                String str = zzaiVar.a;
                com.google.android.gms.common.internal.u.h(str);
                C3874j c3874j2 = this.c;
                L(c3874j2);
                zzai zzaiVarQ0 = c3874j2.Q0(str, zzaiVar.c.b);
                Y y = this.l;
                if (zzaiVarQ0 != null) {
                    c().n.h("Removing conditional user property", zzaiVar.a, y.m.f(zzaiVar.c.b));
                    C3874j c3874j3 = this.c;
                    L(c3874j3);
                    c3874j3.t0(str, zzaiVar.c.b);
                    if (zzaiVarQ0.e) {
                        C3874j c3874j4 = this.c;
                        L(c3874j4);
                        c3874j4.l0(str, zzaiVar.c.b);
                    }
                    zzbh zzbhVar = zzaiVar.k;
                    if (zzbhVar != null) {
                        zzbf zzbfVar = zzbhVar.b;
                        zzbh zzbhVarX = e().X(zzbhVar.a, zzbfVar != null ? zzbfVar.a() : null, zzaiVarQ0.b, zzbhVar.d, true);
                        com.google.android.gms.common.internal.u.h(zzbhVarX);
                        b0(zzbhVarX, zzrVar);
                    }
                } else {
                    c().j.h("Conditional user property doesn't exist", I.a0(zzaiVar.a), y.m.f(zzaiVar.c.b));
                }
                C3874j c3874j5 = this.c;
                L(c3874j5);
                c3874j5.n0();
                C3874j c3874j6 = this.c;
                L(c3874j6);
                c3874j6.h0();
            } catch (Throwable th) {
                C3874j c3874j7 = this.c;
                L(c3874j7);
                c3874j7.h0();
                throw th;
            }
        }
    }

    public final void Q(String str, zzr zzrVar) {
        i().S();
        k();
        if (K(zzrVar)) {
            if (!zzrVar.h) {
                f0(zzrVar);
                return;
            }
            Boolean boolM = M(zzrVar);
            if ("_npa".equals(str) && boolM != null) {
                c().n.f("Falling back to manifest metadata value for ad personalization");
                ((com.google.android.gms.common.util.b) f()).getClass();
                W(new zzqb(System.currentTimeMillis(), Long.valueOf(true != boolM.booleanValue() ? 0L : 1L), "_npa", "auto"), zzrVar);
                return;
            }
            I iC = c();
            Y y = this.l;
            iC.n.g("Removing user property", y.m.f(str));
            C3874j c3874j = this.c;
            L(c3874j);
            c3874j.d0();
            try {
                f0(zzrVar);
                boolean zEquals = FieldType.FOREIGN_ID_FIELD_SUFFIX.equals(str);
                String str2 = zzrVar.a;
                if (zEquals) {
                    C3874j c3874j2 = this.c;
                    L(c3874j2);
                    com.google.android.gms.common.internal.u.h(str2);
                    c3874j2.l0(str2, "_lair");
                }
                C3874j c3874j3 = this.c;
                L(c3874j3);
                com.google.android.gms.common.internal.u.h(str2);
                c3874j3.l0(str2, str);
                C3874j c3874j4 = this.c;
                L(c3874j4);
                c3874j4.n0();
                c().n.g("User property removed", y.m.f(str));
                C3874j c3874j5 = this.c;
                L(c3874j5);
                c3874j5.h0();
            } catch (Throwable th) {
                C3874j c3874j6 = this.c;
                L(c3874j6);
                c3874j6.h0();
                throw th;
            }
        }
    }

    public final void R(zzr zzrVar) throws NumberFormatException {
        Z.l(this);
        String str = zzrVar.a;
        com.google.android.gms.common.internal.u.e(str);
        C3878l c3878lB = C3878l.b(zzrVar.A);
        c().o.h("Setting DMA consent for package", str, c3878lB);
        i().S();
        k();
        EnumC3875j0 enumC3875j0C = C3878l.a(100, d0(str)).c();
        this.C.put(str, c3878lB);
        C3874j c3874j = this.c;
        L(c3874j);
        com.google.android.gms.common.internal.u.h(str);
        com.google.android.gms.common.internal.u.h(c3878lB);
        c3874j.S();
        c3874j.T();
        C3881m0 c3881m0W0 = c3874j.W0(str);
        C3881m0 c3881m0 = C3881m0.c;
        if (c3881m0W0 == c3881m0) {
            c3874j.q0(str, c3881m0);
        }
        ContentValues contentValues = new ContentValues();
        contentValues.put("app_id", str);
        contentValues.put("dma_consent_settings", c3878lB.b);
        c3874j.A0(contentValues);
        EnumC3875j0 enumC3875j0C2 = C3878l.a(100, d0(str)).c();
        Z.l(this);
        EnumC3875j0 enumC3875j0 = EnumC3875j0.DENIED;
        EnumC3875j0 enumC3875j02 = EnumC3875j0.GRANTED;
        boolean z = enumC3875j0C == enumC3875j0 && enumC3875j0C2 == enumC3875j02;
        boolean z2 = enumC3875j0C == enumC3875j02 && enumC3875j0C2 == enumC3875j0;
        if (z || z2) {
            c().o.g("Generated _dcu event for", str);
            Bundle bundle = new Bundle();
            C3874j c3874j2 = this.c;
            L(c3874j2);
            if (c3874j2.S0(v(), str, false, false, false, false).f < h0().Y(str, AbstractC3893t.l0)) {
                bundle.putLong("_r", 1L);
                C3874j c3874j3 = this.c;
                L(c3874j3);
                c().o.h("_dcu realtime event count", str, Long.valueOf(c3874j3.S0(v(), str, false, false, true, false).f));
            }
            this.J.g(str, "_dcu", bundle);
        }
    }

    public final void S(zzr zzrVar) {
        Z.l(this);
        String str = zzrVar.a;
        com.google.android.gms.common.internal.u.e(str);
        C3881m0 c3881m0E = C3881m0.e(zzrVar.z, zzrVar.u);
        n0(str);
        c().o.h("Setting storage consent for package", str, c3881m0E);
        i().S();
        k();
        this.B.put(str, c3881m0E);
        C3874j c3874j = this.c;
        L(c3874j);
        c3874j.q0(str, c3881m0E);
    }

    public final void T(ArrayList arrayList) {
        com.google.android.gms.common.internal.u.b(!arrayList.isEmpty());
        if (this.y != null) {
            c().g.f("Set uploading progress before finishing the previous upload");
        } else {
            this.y = new ArrayList(arrayList);
        }
    }

    public final void U(zzai zzaiVar, zzr zzrVar) {
        zzbh zzbhVar;
        com.google.android.gms.common.internal.u.e(zzaiVar.a);
        com.google.android.gms.common.internal.u.h(zzaiVar.b);
        com.google.android.gms.common.internal.u.h(zzaiVar.c);
        com.google.android.gms.common.internal.u.e(zzaiVar.c.b);
        i().S();
        k();
        if (K(zzrVar)) {
            if (!zzrVar.h) {
                f0(zzrVar);
                return;
            }
            zzai zzaiVar2 = new zzai(zzaiVar);
            boolean z = false;
            zzaiVar2.e = false;
            C3874j c3874j = this.c;
            L(c3874j);
            c3874j.d0();
            try {
                C3874j c3874j2 = this.c;
                L(c3874j2);
                String str = zzaiVar2.a;
                com.google.android.gms.common.internal.u.h(str);
                zzai zzaiVarQ0 = c3874j2.Q0(str, zzaiVar2.c.b);
                Y y = this.l;
                if (zzaiVarQ0 != null && !zzaiVarQ0.b.equals(zzaiVar2.b)) {
                    c().j.i("Updating a conditional user property with different origin. name, origin, origin (from DB)", y.m.f(zzaiVar2.c.b), zzaiVar2.b, zzaiVarQ0.b);
                }
                if (zzaiVarQ0 != null && zzaiVarQ0.e) {
                    zzaiVar2.b = zzaiVarQ0.b;
                    zzaiVar2.d = zzaiVarQ0.d;
                    zzaiVar2.h = zzaiVarQ0.h;
                    zzaiVar2.f = zzaiVarQ0.f;
                    zzaiVar2.i = zzaiVarQ0.i;
                    zzaiVar2.e = true;
                    zzqb zzqbVar = zzaiVar2.c;
                    zzaiVar2.c = new zzqb(zzaiVarQ0.c.c, zzqbVar.a(), zzqbVar.b, zzaiVarQ0.c.f);
                } else if (TextUtils.isEmpty(zzaiVar2.f)) {
                    zzqb zzqbVar2 = zzaiVar2.c;
                    zzaiVar2.c = new zzqb(zzaiVar2.d, zzqbVar2.a(), zzqbVar2.b, zzaiVar2.c.f);
                    zzaiVar2.e = true;
                    z = true;
                }
                if (zzaiVar2.e) {
                    zzqb zzqbVar3 = zzaiVar2.c;
                    String str2 = zzaiVar2.a;
                    com.google.android.gms.common.internal.u.h(str2);
                    String str3 = zzaiVar2.b;
                    String str4 = zzqbVar3.b;
                    long j = zzqbVar3.c;
                    Object objA = zzqbVar3.a();
                    com.google.android.gms.common.internal.u.h(objA);
                    v1 v1Var = new v1(str2, str3, str4, j, objA);
                    Object obj = v1Var.e;
                    String str5 = v1Var.c;
                    C3874j c3874j3 = this.c;
                    L(c3874j3);
                    if (c3874j3.G0(v1Var)) {
                        c().n.i("User property updated immediately", zzaiVar2.a, y.m.f(str5), obj);
                    } else {
                        c().g.i("(2)Too many active user properties, ignoring", I.a0(zzaiVar2.a), y.m.f(str5), obj);
                    }
                    if (z && (zzbhVar = zzaiVar2.i) != null) {
                        b0(new zzbh(zzbhVar, zzaiVar2.d), zzrVar);
                    }
                }
                C3874j c3874j4 = this.c;
                L(c3874j4);
                if (c3874j4.F0(zzaiVar2)) {
                    c().n.i("Conditional property added", zzaiVar2.a, y.m.f(zzaiVar2.c.b), zzaiVar2.c.a());
                } else {
                    c().g.i("Too many conditional properties, ignoring", I.a0(zzaiVar2.a), y.m.f(zzaiVar2.c.b), zzaiVar2.c.a());
                }
                C3874j c3874j5 = this.c;
                L(c3874j5);
                c3874j5.n0();
                C3874j c3874j6 = this.c;
                L(c3874j6);
                c3874j6.h0();
            } catch (Throwable th) {
                C3874j c3874j7 = this.c;
                L(c3874j7);
                c3874j7.h0();
                throw th;
            }
        }
    }

    public final void V(String str, boolean z, Long l, Long l2) {
        C3874j c3874j = this.c;
        L(c3874j);
        F fP0 = c3874j.P0(str);
        if (fP0 != null) {
            Y y = fP0.a;
            X x = y.j;
            Y.k(x);
            x.S();
            fP0.R |= fP0.z != z;
            fP0.z = z;
            X x2 = y.j;
            Y.k(x2);
            x2.S();
            fP0.R |= !Objects.equals(fP0.A, l);
            fP0.A = l;
            X x3 = y.j;
            Y.k(x3);
            x3.S();
            fP0.R |= !Objects.equals(fP0.B, l2);
            fP0.B = l2;
            if (fP0.s()) {
                C3874j c3874j2 = this.c;
                L(c3874j2);
                c3874j2.o0(fP0, false);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x00cd  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void W(com.google.android.gms.measurement.internal.zzqb r24, com.google.android.gms.measurement.internal.zzr r25) {
        /*
            Method dump skipped, instructions count: 503
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.W(com.google.android.gms.measurement.internal.zzqb, com.google.android.gms.measurement.internal.zzr):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:73:0x01a6 A[Catch: all -> 0x0021, TryCatch #0 {all -> 0x0021, blocks: (B:3:0x0007, B:5:0x0014, B:8:0x0024, B:10:0x002a, B:11:0x0037, B:13:0x003f, B:14:0x0044, B:16:0x004f, B:17:0x005c, B:19:0x0067, B:20:0x0077, B:22:0x00a3, B:24:0x00a9, B:25:0x00ac, B:27:0x00c5, B:28:0x00da, B:30:0x00eb, B:32:0x00f1, B:35:0x0106, B:45:0x0125, B:47:0x012a, B:48:0x012d, B:49:0x012e, B:50:0x0133, B:55:0x0178, B:71:0x01a0, B:73:0x01a6, B:75:0x01b1, B:79:0x01bc, B:80:0x01bf, B:33:0x00f6, B:37:0x010a, B:42:0x0112), top: B:83:0x0007, inners: #6 }] */
    /* JADX WARN: Type inference failed for: r11v0, types: [com.google.android.gms.measurement.internal.r1] */
    /* JADX WARN: Type inference failed for: r1v13, types: [long] */
    /* JADX WARN: Type inference failed for: r1v14 */
    /* JADX WARN: Type inference failed for: r1v18 */
    /* JADX WARN: Type inference failed for: r1v19 */
    /* JADX WARN: Type inference failed for: r1v23, types: [android.database.Cursor] */
    /* JADX WARN: Type inference failed for: r1v26, types: [android.database.Cursor] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void X() {
        /*
            Method dump skipped, instructions count: 454
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.X():void");
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x00bc, code lost:
    
        r22 = r11;
     */
    /* JADX WARN: Removed duplicated region for block: B:108:0x0231  */
    /* JADX WARN: Removed duplicated region for block: B:111:0x023a  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x029c  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x049d  */
    /* JADX WARN: Removed duplicated region for block: B:180:0x04a0  */
    /* JADX WARN: Removed duplicated region for block: B:190:0x04ed  */
    /* JADX WARN: Removed duplicated region for block: B:213:0x0575  */
    /* JADX WARN: Removed duplicated region for block: B:214:0x0578  */
    /* JADX WARN: Removed duplicated region for block: B:288:0x07b4  */
    /* JADX WARN: Removed duplicated region for block: B:294:0x07e4  */
    /* JADX WARN: Removed duplicated region for block: B:297:0x07fd  */
    /* JADX WARN: Removed duplicated region for block: B:301:0x081a A[LOOP:5: B:299:0x0814->B:301:0x081a, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:304:0x0859  */
    /* JADX WARN: Removed duplicated region for block: B:309:0x0876  */
    /* JADX WARN: Removed duplicated region for block: B:317:0x08cf A[LOOP:6: B:315:0x08c9->B:317:0x08cf, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:320:0x091f  */
    /* JADX WARN: Removed duplicated region for block: B:324:0x095f  */
    /* JADX WARN: Removed duplicated region for block: B:330:0x097b  */
    /* JADX WARN: Removed duplicated region for block: B:340:0x0a10  */
    /* JADX WARN: Removed duplicated region for block: B:352:0x0a75  */
    /* JADX WARN: Removed duplicated region for block: B:385:0x07c9 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:404:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void Y(long r32, java.lang.String r34) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 2681
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.Y(long, java.lang.String):void");
    }

    public final void Z(String str) {
        Z.l(this);
        this.v = true;
        try {
            Y y = this.l;
            y.getClass();
            Boolean bool = y.r().f;
            if (bool == null) {
                c().j.f("Upload data called on the client side before use of service was decided");
            } else if (bool.booleanValue()) {
                c().g.f("Upload called in the client side when service should be used");
            } else if (this.o > 0) {
                F();
            } else {
                M m = this.b;
                L(m);
                if (m.r0()) {
                    C3874j c3874j = this.c;
                    L(c3874j);
                    if (c3874j.r0(str)) {
                        C3874j c3874j2 = this.c;
                        L(c3874j2);
                        t1 t1VarX0 = c3874j2.X0(str);
                        if (t1VarX0 != null) {
                            C2964a1 c2964a1 = t1VarX0.b;
                            c().o.i("[sgtm] Uploading data from upload queue. appId, type, url", str, t1VarX0.e, t1VarX0.c);
                            byte[] bArrC = c2964a1.c();
                            if (Log.isLoggable(c().d0(), 2)) {
                                M m2 = this.g;
                                L(m2);
                                c().o.i("[sgtm] Uploading data from upload queue. appId, uncompressed size, data", str, Integer.valueOf(bArrC.length), m2.z0(c2964a1));
                            }
                            this.u = true;
                            M m3 = this.b;
                            L(m3);
                            m3.q0(str, new n1(t1VarX0.c, t1VarX0.d, t1VarX0.e, null), c2964a1, new com.quizlet.data.repository.classfolder.e(this, str, t1VarX0));
                        }
                    } else {
                        c().o.g("[sgtm] Upload queue has no batches for appId", str);
                    }
                } else {
                    c().o.f("Network not connected, ignoring upload request");
                    F();
                }
            }
            this.v = false;
            C();
        } catch (Throwable th) {
            this.v = false;
            C();
            throw th;
        }
    }

    public final M a() {
        M m = this.g;
        L(m);
        return m;
    }

    public final void a0(String str, com.google.android.gms.internal.measurement.W0 w0, Bundle bundle, String str2) {
        int iMax;
        List listUnmodifiableList = Collections.unmodifiableList(Arrays.asList("_o", "_sn", "_sc", "_si"));
        if (x1.L0(((com.google.android.gms.internal.measurement.X0) w0.b).s()) || x1.L0(str)) {
            C3864e c3864eH0 = h0();
            c3864eH0.getClass();
            iMax = Math.max(Math.max(Math.min(c3864eH0.Y(str2, AbstractC3893t.g0), com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR), 100), 256);
        } else {
            C3864e c3864eH02 = h0();
            c3864eH02.getClass();
            iMax = Math.max(Math.min(c3864eH02.Y(str2, AbstractC3893t.g0), com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR), 100);
        }
        long j = iMax;
        long jCodePointCount = ((com.google.android.gms.internal.measurement.X0) w0.b).t().codePointCount(0, ((com.google.android.gms.internal.measurement.X0) w0.b).t().length());
        e();
        String strS = ((com.google.android.gms.internal.measurement.X0) w0.b).s();
        h0();
        String strB0 = x1.b0(strS, 40, true);
        if (jCodePointCount <= j || listUnmodifiableList.contains(((com.google.android.gms.internal.measurement.X0) w0.b).s())) {
            return;
        }
        if ("_ev".equals(((com.google.android.gms.internal.measurement.X0) w0.b).s())) {
            e();
            String strT = ((com.google.android.gms.internal.measurement.X0) w0.b).t();
            C3864e c3864eH03 = h0();
            c3864eH03.getClass();
            bundle.putString("_ev", x1.b0(strT, Math.max(Math.max(Math.min(c3864eH03.Y(str2, AbstractC3893t.g0), com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR), 100), 256), true));
            return;
        }
        c().l.h("Param value is too long; discarded. Name, value length", strB0, Long.valueOf(jCodePointCount));
        if (bundle.getLong("_err") == 0) {
            bundle.putLong("_err", 4L);
            if (bundle.getString("_ev") == null) {
                bundle.putString("_ev", strB0);
                bundle.putLong("_el", jCodePointCount);
            }
        }
        bundle.remove(((com.google.android.gms.internal.measurement.X0) w0.b).s());
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public final com.google.android.material.shape.e b() {
        return this.l.f;
    }

    /* JADX WARN: Can't wrap try/catch for region: R(13:(1:262)(33:264|(2:265|(3:267|(3:405|269|(2:271|(2:273|417)(1:420))(1:419))(1:418)|277)(2:416|279))|280|(1:282)|(1:284)|285|(1:287)|288|(1:318)(4:292|(1:294)(1:295)|296|(4:298|(1:300)|301|(0)(3:307|308|(5:310|(1:312)(1:313)|314|(1:316)|317)(0)))(0))|319|(2:321|(1:323)(2:324|325))|326|(3:328|(1:330)|331)(1:332)|333|(1:337)|338|(1:340)|341|(4:344|(2:346|(4:348|(1:350)(1:351)|352|(2:354|424)(1:423))(2:356|422))(0)|357|342)|401|358|397|359|360|(2:361|(2:363|(1:426)(1:427))(3:425|366|(1:370)))|365|371|395|372|(1:374)(2:378|379)|388|389|390)|397|359|360|(3:361|(0)(0)|427)|365|371|395|372|(0)(0)|388|389|390) */
    /* JADX WARN: Can't wrap try/catch for region: R(59:123|(2:125|(3:127|(1:129)|130))(1:131)|132|133|(1:135)|136|(2:140|(1:142))|143|(2:403|153)|154|155|156|399|157|158|161|(1:163)|164|(2:166|(2:172|173)(1:169))(1:174)|175|(1:177)|178|(1:180)(1:181)|182|(1:184)(1:185)|186|(1:188)(1:190)|191|(2:193|194)|195|(1:197)(1:198)|199|(1:203)|204|205|(2:207|(6:209|(1:213)|214|(1:216)(1:217)|218|(1:220)(15:221|(1:223)(1:224)|225|(1:227)(1:228)|229|(1:231)(1:232)|233|(1:235)(1:236)|237|(1:239)(1:240)|241|(1:243)(1:244)|245|(1:247)(1:248)|249))(1:251))(0)|252|(1:254)|255|(1:257)(1:258)|(13:(1:262)(33:264|(2:265|(3:267|(3:405|269|(2:271|(2:273|417)(1:420))(1:419))(1:418)|277)(2:416|279))|280|(1:282)|(1:284)|285|(1:287)|288|(1:318)(4:292|(1:294)(1:295)|296|(4:298|(1:300)|301|(0)(3:307|308|(5:310|(1:312)(1:313)|314|(1:316)|317)(0)))(0))|319|(2:321|(1:323)(2:324|325))|326|(3:328|(1:330)|331)(1:332)|333|(1:337)|338|(1:340)|341|(4:344|(2:346|(4:348|(1:350)(1:351)|352|(2:354|424)(1:423))(2:356|422))(0)|357|342)|401|358|397|359|360|(2:361|(2:363|(1:426)(1:427))(3:425|366|(1:370)))|365|371|395|372|(1:374)(2:378|379)|388|389|390)|397|359|360|(3:361|(0)(0)|427)|365|371|395|372|(0)(0)|388|389|390)|263|(0)|285|(0)|288|(2:290|318)(0)|319|(0)|326|(0)(0)|333|(2:335|337)|338|(0)|341|(1:342)|401|358) */
    /* JADX WARN: Code restructure failed: missing block: B:376:0x0c43, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:380:0x0c4a, code lost:
    
        ((com.google.android.gms.measurement.internal.Y) r2.b).c().X().h("Error storing raw event. appId", com.google.android.gms.measurement.internal.I.a0((java.lang.String) r15.d), r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:382:0x0c64, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:387:0x0c81, code lost:
    
        c().X().h("Data loss. Failed to insert raw event metadata. appId", com.google.android.gms.measurement.internal.I.a0(r3.z()), r0);
     */
    /* JADX WARN: Removed duplicated region for block: B:100:0x0360  */
    /* JADX WARN: Removed duplicated region for block: B:102:0x0365 A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:111:0x03d2 A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:115:0x03f7  */
    /* JADX WARN: Removed duplicated region for block: B:123:0x044b  */
    /* JADX WARN: Removed duplicated region for block: B:251:0x07b9  */
    /* JADX WARN: Removed duplicated region for block: B:284:0x0895 A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:287:0x08a5 A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:318:0x0977  */
    /* JADX WARN: Removed duplicated region for block: B:321:0x09bd A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:328:0x09dd A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:332:0x0a3f  */
    /* JADX WARN: Removed duplicated region for block: B:340:0x0a66 A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:344:0x0a7f A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:356:0x0b15  */
    /* JADX WARN: Removed duplicated region for block: B:363:0x0b82 A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:374:0x0c2d A[Catch: all -> 0x01d1, SQLiteException -> 0x0c43, TRY_LEAVE, TryCatch #1 {SQLiteException -> 0x0c43, blocks: (B:372:0x0c1c, B:374:0x0c2d), top: B:395:0x0c1c, outer: #0 }] */
    /* JADX WARN: Removed duplicated region for block: B:378:0x0c45  */
    /* JADX WARN: Removed duplicated region for block: B:425:0x0b90 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:55:0x01ec A[PHI: r42 r43
  0x01ec: PHI (r42v9 java.lang.String) = (r42v0 java.lang.String), (r42v0 java.lang.String), (r42v10 java.lang.String) binds: [B:74:0x025d, B:76:0x026b, B:54:0x01e8] A[DONT_GENERATE, DONT_INLINE]
  0x01ec: PHI (r43v8 java.lang.String) = (r43v1 java.lang.String), (r43v1 java.lang.String), (r43v9 java.lang.String) binds: [B:74:0x025d, B:76:0x026b, B:54:0x01e8] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:60:0x01fc A[Catch: all -> 0x01d1, TRY_ENTER, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:72:0x0253 A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x025f A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0283  */
    /* JADX WARN: Removed duplicated region for block: B:96:0x031a A[Catch: all -> 0x01d1, TryCatch #0 {all -> 0x01d1, blocks: (B:38:0x01b2, B:41:0x01bf, B:43:0x01c7, B:49:0x01d4, B:98:0x0353, B:109:0x0391, B:111:0x03d2, B:113:0x03d7, B:114:0x03ee, B:116:0x03f9, B:118:0x0413, B:120:0x0419, B:121:0x0430, B:125:0x0451, B:129:0x0478, B:130:0x048f, B:132:0x049a, B:135:0x04b7, B:136:0x04cb, B:138:0x04d3, B:140:0x04dd, B:142:0x04e3, B:143:0x04ea, B:145:0x04f7, B:147:0x04ff, B:149:0x0507, B:151:0x050d, B:153:0x0511, B:154:0x051d, B:156:0x0525, B:157:0x052e, B:163:0x056e, B:164:0x0583, B:166:0x05ae, B:169:0x05d6, B:173:0x0624, B:175:0x0651, B:177:0x0680, B:178:0x0683, B:180:0x0689, B:182:0x0691, B:184:0x0697, B:186:0x069f, B:188:0x06a5, B:194:0x06b7, B:195:0x06ba, B:197:0x06c5, B:199:0x06d1, B:201:0x06fd, B:203:0x0703, B:204:0x0708, B:207:0x0719, B:209:0x0722, B:213:0x0737, B:218:0x0744, B:254:0x07c1, B:255:0x07c4, B:257:0x07ef, B:260:0x07f8, B:264:0x0803, B:265:0x081d, B:267:0x0823, B:269:0x083d, B:271:0x0849, B:273:0x0856, B:280:0x088b, B:284:0x0895, B:285:0x0898, B:287:0x08a5, B:288:0x08a8, B:290:0x08bc, B:292:0x08c0, B:294:0x08cb, B:296:0x08d9, B:298:0x08e3, B:300:0x08ee, B:301:0x08f7, B:303:0x0903, B:305:0x090f, B:308:0x091b, B:310:0x0927, B:312:0x093d, B:314:0x0957, B:316:0x0963, B:317:0x096c, B:319:0x097c, B:321:0x09bd, B:324:0x09c8, B:325:0x09d2, B:326:0x09d3, B:328:0x09dd, B:330:0x09fd, B:331:0x0a08, B:333:0x0a40, B:335:0x0a48, B:337:0x0a52, B:338:0x0a5c, B:340:0x0a66, B:341:0x0a70, B:342:0x0a79, B:344:0x0a7f, B:346:0x0ac9, B:348:0x0adb, B:352:0x0afa, B:354:0x0b0a, B:351:0x0aea, B:358:0x0b1d, B:359:0x0b5f, B:360:0x0b6a, B:361:0x0b7c, B:363:0x0b82, B:371:0x0bcc, B:372:0x0c1c, B:374:0x0c2d, B:388:0x0c96, B:379:0x0c47, B:380:0x0c4a, B:366:0x0b90, B:368:0x0bba, B:385:0x0c67, B:386:0x0c80, B:387:0x0c81, B:295:0x08d0, B:278:0x0877, B:258:0x07f2, B:221:0x074d, B:225:0x075a, B:229:0x0768, B:233:0x0776, B:237:0x0784, B:241:0x0792, B:245:0x079e, B:249:0x07ac, B:174:0x0641, B:160:0x0557, B:102:0x0365, B:103:0x0371, B:105:0x0377, B:107:0x0385, B:57:0x01f2, B:60:0x01fc, B:62:0x0211, B:68:0x0229, B:73:0x0259, B:75:0x025f, B:77:0x026d, B:79:0x027d, B:82:0x0287, B:94:0x0310, B:96:0x031a, B:83:0x02ae, B:84:0x02c7, B:86:0x02cd, B:93:0x02f5, B:92:0x02e0, B:71:0x0235, B:72:0x0253), top: B:394:0x01b2, inners: #1, #3, #4, #6 }] */
    /* JADX WARN: Removed duplicated region for block: B:97:0x034f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b0(com.google.android.gms.measurement.internal.zzbh r50, com.google.android.gms.measurement.internal.zzr r51) throws java.net.MalformedURLException {
        /*
            Method dump skipped, instructions count: 3279
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.b0(com.google.android.gms.measurement.internal.zzbh, com.google.android.gms.measurement.internal.zzr):void");
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public final I c() {
        Y y = this.l;
        com.google.android.gms.common.internal.u.h(y);
        I i = y.i;
        Y.k(i);
        return i;
    }

    public final boolean c0(String str, String str2) {
        C3874j c3874j = this.c;
        L(c3874j);
        F fP0 = c3874j.P0(str);
        HashMap map = this.E;
        if (fP0 != null && e().H0(str, fP0.i())) {
            map.remove(str2);
            return true;
        }
        q1 q1Var = (q1) map.get(str2);
        if (q1Var != null) {
            ((com.google.android.gms.common.util.b) q1Var.a.f()).getClass();
            if (System.currentTimeMillis() < q1Var.c) {
                return false;
            }
        }
        return true;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public final Context d() {
        return this.l.a;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final Bundle d0(String str) {
        Z.l(this);
        T t = this.a;
        L(t);
        if (t.g0(str) == null) {
            return null;
        }
        Bundle bundle = new Bundle();
        C3881m0 c3881m0N0 = n0(str);
        Bundle bundle2 = new Bundle();
        Iterator it2 = c3881m0N0.a.entrySet().iterator();
        while (true) {
            if (!it2.hasNext()) {
                break;
            }
            Map.Entry entry = (Map.Entry) it2.next();
            int iOrdinal = ((EnumC3875j0) entry.getValue()).ordinal();
            String str2 = iOrdinal != 2 ? iOrdinal != 3 ? null : "granted" : "denied";
            if (str2 != null) {
                bundle2.putString(((EnumC3879l0) entry.getKey()).a, str2);
            }
        }
        bundle.putAll(bundle2);
        C3878l c3878lJ0 = j0(str, k0(str), c3881m0N0, new androidx.webkit.internal.p(19));
        Bundle bundle3 = new Bundle();
        for (Map.Entry entry2 : c3878lJ0.e.entrySet()) {
            int iOrdinal2 = ((EnumC3875j0) entry2.getValue()).ordinal();
            String str3 = iOrdinal2 != 2 ? iOrdinal2 != 3 ? null : "granted" : "denied";
            if (str3 != null) {
                bundle3.putString(((EnumC3879l0) entry2.getKey()).a, str3);
            }
        }
        Boolean bool = c3878lJ0.c;
        if (bool != null) {
            bundle3.putString("is_dma_region", bool.toString());
        }
        String str4 = c3878lJ0.d;
        if (str4 != null) {
            bundle3.putString("cps_display_str", str4);
        }
        bundle.putAll(bundle3);
        C3874j c3874j = this.c;
        L(c3874j);
        v1 v1VarY0 = c3874j.Y0(str, "_npa");
        bundle.putString("ad_personalization", 1 != (v1VarY0 != null ? v1VarY0.e.equals(1L) : y(str, new androidx.webkit.internal.p(19))) ? "granted" : "denied");
        return bundle;
    }

    public final x1 e() {
        Y y = this.l;
        com.google.android.gms.common.internal.u.h(y);
        x1 x1Var = y.l;
        Y.h(x1Var);
        return x1Var;
    }

    public final Bundle e0(zzbh zzbhVar, String str) {
        Bundle bundle = new Bundle();
        bundle.putLong("_sid", zzbhVar.b.a.getLong("_sid"));
        C3874j c3874j = this.c;
        L(c3874j);
        v1 v1VarY0 = c3874j.Y0(str, "_sno");
        if (v1VarY0 != null) {
            Object obj = v1VarY0.e;
            if (obj instanceof Long) {
                bundle.putLong("_sno", ((Long) obj).longValue());
            }
        }
        return bundle;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public final com.google.android.gms.common.util.a f() {
        Y y = this.l;
        com.google.android.gms.common.internal.u.h(y);
        return y.n;
    }

    /* JADX WARN: Removed duplicated region for block: B:103:0x02ad  */
    /* JADX WARN: Removed duplicated region for block: B:106:0x02b1  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x012f  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x015a  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0165  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0170  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x017c  */
    /* JADX WARN: Removed duplicated region for block: B:65:0x0191  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x01a4  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x01a6  */
    /* JADX WARN: Removed duplicated region for block: B:72:0x01f6  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x01fc  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0221  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0223  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x0239  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x023b  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0250  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x027d  */
    /* JADX WARN: Removed duplicated region for block: B:94:0x027f  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x0291  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.F f0(com.google.android.gms.measurement.internal.zzr r13) {
        /*
            Method dump skipped, instructions count: 699
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.f0(com.google.android.gms.measurement.internal.zzr):com.google.android.gms.measurement.internal.F");
    }

    public final String g(C3881m0 c3881m0) {
        if (!c3881m0.k(EnumC3879l0.ANALYTICS_STORAGE)) {
            return null;
        }
        byte[] bArr = new byte[16];
        e().d0().nextBytes(bArr);
        return String.format(Locale.US, "%032x", new BigInteger(1, bArr));
    }

    public final C3860c g0() {
        C3860c c3860c = this.f;
        L(c3860c);
        return c3860c;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v3, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r0v5, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r0v7, types: [java.util.List] */
    public final List h(Bundle bundle, zzr zzrVar) {
        i().S();
        E3.b();
        C3864e c3864eH0 = h0();
        String str = zzrVar.a;
        if (!c3864eH0.f0(str, AbstractC3893t.V0) || str == null) {
            return new ArrayList();
        }
        if (bundle != null) {
            int[] intArray = bundle.getIntArray("uriSources");
            long[] longArray = bundle.getLongArray("uriTimestamps");
            if (intArray != null) {
                if (longArray == null || longArray.length != intArray.length) {
                    c().g.f("Uri sources and timestamps do not match");
                } else {
                    for (int i = 0; i < intArray.length; i++) {
                        C3874j c3874j = this.c;
                        L(c3874j);
                        Y y = (Y) c3874j.b;
                        int i2 = intArray[i];
                        long j = longArray[i];
                        com.google.android.gms.common.internal.u.e(str);
                        c3874j.S();
                        c3874j.T();
                        try {
                            int iDelete = c3874j.O0().delete("trigger_uris", "app_id=? and source=? and timestamp_millis<=?", new String[]{str, String.valueOf(i2), String.valueOf(j)});
                            I i3 = y.i;
                            Y.k(i3);
                            i3.o.i("Pruned " + iDelete + " trigger URIs. appId, source, timestamp", str, Integer.valueOf(i2), Long.valueOf(j));
                        } catch (SQLiteException e) {
                            I i4 = y.i;
                            Y.k(i4);
                            i4.g.h("Error pruning trigger URIs. appId", I.a0(str), e);
                        }
                    }
                }
            }
        }
        C3874j c3874j2 = this.c;
        L(c3874j2);
        String str2 = zzrVar.a;
        com.google.android.gms.common.internal.u.e(str2);
        c3874j2.S();
        c3874j2.T();
        ?? arrayList = new ArrayList();
        Cursor cursorQuery = null;
        try {
            try {
                cursorQuery = c3874j2.O0().query("trigger_uris", new String[]{"trigger_uri", "timestamp_millis", "source"}, "app_id=?", new String[]{str2}, null, null, "rowid", null);
                if (cursorQuery.moveToFirst()) {
                    do {
                        String string = cursorQuery.getString(0);
                        if (string == null) {
                            string = "";
                        }
                        arrayList.add(new zzov(cursorQuery.getInt(2), cursorQuery.getLong(1), string));
                    } while (cursorQuery.moveToNext());
                }
            } catch (SQLiteException e2) {
                I i5 = ((Y) c3874j2.b).i;
                Y.k(i5);
                i5.g.h("Error querying trigger uris. appId", I.a0(str2), e2);
                arrayList = Collections.EMPTY_LIST;
            }
            if (cursorQuery != null) {
                cursorQuery.close();
            }
            return arrayList;
        } finally {
        }
    }

    public final C3864e h0() {
        Y y = this.l;
        com.google.android.gms.common.internal.u.h(y);
        return y.g;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3873i0
    public final X i() {
        Y y = this.l;
        com.google.android.gms.common.internal.u.h(y);
        X x = y.j;
        Y.k(x);
        return x;
    }

    public final C3874j i0() {
        C3874j c3874j = this.c;
        L(c3874j);
        return c3874j;
    }

    public final void j() {
        Z.l(this);
        if (this.n) {
            return;
        }
        this.n = true;
        i().S();
        FileLock fileLock = this.w;
        Y y = this.l;
        if (fileLock == null || !fileLock.isValid()) {
            ((Y) this.c.b).getClass();
            try {
                FileChannel channel = new RandomAccessFile(new File(new File(y.a.getFilesDir(), "google_app_measurement.db").getPath()), "rw").getChannel();
                this.x = channel;
                FileLock fileLockTryLock = channel.tryLock();
                this.w = fileLockTryLock;
                if (fileLockTryLock == null) {
                    c().g.f("Storage concurrent data access panic");
                    return;
                }
                c().o.f("Storage concurrent access okay");
            } catch (FileNotFoundException e) {
                c().g.g("Failed to acquire storage lock", e);
                return;
            } catch (IOException e2) {
                c().g.g("Failed to access storage lock file", e2);
                return;
            } catch (OverlappingFileLockException e3) {
                c().j.g("Storage lock already acquired", e3);
                return;
            }
        } else {
            c().o.f("Storage concurrent access okay");
        }
        FileChannel fileChannel = this.x;
        i().S();
        int i = 0;
        if (fileChannel == null || !fileChannel.isOpen()) {
            c().g.f("Bad channel to read from");
        } else {
            ByteBuffer byteBufferAllocate = ByteBuffer.allocate(4);
            try {
                fileChannel.position(0L);
                int i2 = fileChannel.read(byteBufferAllocate);
                if (i2 == 4) {
                    byteBufferAllocate.flip();
                    i = byteBufferAllocate.getInt();
                } else if (i2 != -1) {
                    c().j.g("Unexpected data length. Bytes read", Integer.valueOf(i2));
                }
            } catch (IOException e4) {
                c().g.g("Failed to read from channel", e4);
            }
        }
        A aN = y.n();
        aN.Q();
        int i3 = aN.f;
        i().S();
        if (i > i3) {
            I iC = c();
            iC.g.h("Panic: can't downgrade version. Previous, current version", Integer.valueOf(i), Integer.valueOf(i3));
            return;
        }
        if (i < i3) {
            FileChannel fileChannel2 = this.x;
            i().S();
            if (fileChannel2 == null || !fileChannel2.isOpen()) {
                c().g.f("Bad channel to read from");
            } else {
                ByteBuffer byteBufferAllocate2 = ByteBuffer.allocate(4);
                byteBufferAllocate2.putInt(i3);
                byteBufferAllocate2.flip();
                try {
                    fileChannel2.truncate(0L);
                    fileChannel2.write(byteBufferAllocate2);
                    fileChannel2.force(true);
                    if (fileChannel2.size() != 4) {
                        c().g.g("Error writing to channel. Bytes written", Long.valueOf(fileChannel2.size()));
                    }
                    I iC2 = c();
                    iC2.o.h("Storage version upgraded. Previous, current version", Integer.valueOf(i), Integer.valueOf(i3));
                    return;
                } catch (IOException e5) {
                    c().g.g("Failed to write to channel", e5);
                }
            }
            I iC3 = c();
            iC3.g.h("Storage version upgrade failed. Previous, current version", Integer.valueOf(i), Integer.valueOf(i3));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x0092  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00a5  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00b2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.measurement.internal.C3878l j0(java.lang.String r12, com.google.android.gms.measurement.internal.C3878l r13, com.google.android.gms.measurement.internal.C3881m0 r14, androidx.webkit.internal.p r15) {
        /*
            Method dump skipped, instructions count: 301
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.j0(java.lang.String, com.google.android.gms.measurement.internal.l, com.google.android.gms.measurement.internal.m0, androidx.webkit.internal.p):com.google.android.gms.measurement.internal.l");
    }

    public final void k() {
        if (!this.m.get()) {
            throw new IllegalStateException("UploadController is not initialized");
        }
    }

    public final C3878l k0(String str) throws NumberFormatException {
        Z.l(this);
        HashMap map = this.C;
        C3878l c3878l = (C3878l) map.get(str);
        if (c3878l != null) {
            return c3878l;
        }
        C3874j c3874j = this.c;
        L(c3874j);
        com.google.android.gms.common.internal.u.h(str);
        c3874j.S();
        c3874j.T();
        C3878l c3878lB = C3878l.b(c3874j.x0("select dma_consent_settings from consent_settings where app_id=? limit 1;", new String[]{str}));
        map.put(str, c3878lB);
        return c3878lB;
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x0123  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void l(com.google.android.gms.internal.measurement.C2969b1 r9, java.lang.String r10) {
        /*
            Method dump skipped, instructions count: 359
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.l(com.google.android.gms.internal.measurement.b1, java.lang.String):void");
    }

    public final com.android.billingclient.api.C l0() {
        com.android.billingclient.api.C c = this.d;
        if (c != null) {
            return c;
        }
        throw new IllegalStateException("Network broadcast receiver not created");
    }

    public final void m(F f) throws MalformedURLException {
        C0208f c0208f;
        C0208f c0208f2;
        i().S();
        if (TextUtils.isEmpty(f.g()) && TextUtils.isEmpty(f.a())) {
            String strC = f.c();
            com.google.android.gms.common.internal.u.h(strC);
            t(strC, 204, null, null, null);
            return;
        }
        String strC2 = f.c();
        com.google.android.gms.common.internal.u.h(strC2);
        c().o.g("Fetching remote configuration", strC2);
        T t = this.a;
        L(t);
        com.google.android.gms.internal.measurement.E0 e0H0 = t.h0(strC2);
        L(t);
        t.S();
        String str = (String) t.n.get(strC2);
        if (e0H0 != null) {
            if (TextUtils.isEmpty(str)) {
                c0208f2 = null;
            } else {
                c0208f2 = new C0208f(0);
                c0208f2.put("If-Modified-Since", str);
            }
            L(t);
            t.S();
            String str2 = (String) t.o.get(strC2);
            if (!TextUtils.isEmpty(str2)) {
                if (c0208f2 == null) {
                    c0208f2 = new C0208f(0);
                }
                c0208f2.put("If-None-Match", str2);
            }
            c0208f = c0208f2;
        } else {
            c0208f = null;
        }
        this.t = true;
        M m = this.b;
        L(m);
        androidx.webkit.internal.p pVar = new androidx.webkit.internal.p(this, 20);
        Y y = (Y) m.b;
        m.S();
        m.T();
        o1 o1Var = m.c.j;
        Uri.Builder builder = new Uri.Builder();
        String strG = f.g();
        if (TextUtils.isEmpty(strG)) {
            strG = f.a();
        }
        Uri.Builder builderAppendQueryParameter = builder.scheme((String) AbstractC3893t.f.a(null)).encodedAuthority((String) AbstractC3893t.g.a(null)).path("config/app/".concat(String.valueOf(strG))).appendQueryParameter("platform", DtbConstants.NATIVE_OS_NAME);
        ((Y) o1Var.b).g.Z();
        builderAppendQueryParameter.appendQueryParameter("gmp_version", String.valueOf(119002L)).appendQueryParameter("runtime_version", "0");
        String string = builder.build().toString();
        try {
            URL url = new URI(string).toURL();
            X x = y.j;
            Y.k(x);
            x.b0(new L(m, f.c(), url, (byte[]) null, c0208f, pVar));
        } catch (IllegalArgumentException | MalformedURLException | URISyntaxException unused) {
            I i = y.i;
            Y.k(i);
            i.g.h("Failed to parse config URL. Not fetching. appId", I.a0(f.c()), string);
        }
    }

    public final T m0() {
        T t = this.a;
        L(t);
        return t;
    }

    public final void n(zzr zzrVar, long j) throws Throwable {
        C3874j c3874j = this.c;
        L(c3874j);
        String str = zzrVar.a;
        com.google.android.gms.common.internal.u.h(str);
        F fP0 = c3874j.P0(str);
        if (fP0 != null) {
            if (e().P0(zzrVar.b, fP0.g(), zzrVar.p, fP0.a())) {
                c().j.g("New GMP App Id passed in. Removing cached database data. appId", I.a0(fP0.c()));
                C3874j c3874j2 = this.c;
                L(c3874j2);
                Y y = (Y) c3874j2.b;
                String strC = fP0.c();
                c3874j2.T();
                c3874j2.S();
                com.google.android.gms.common.internal.u.e(strC);
                try {
                    SQLiteDatabase sQLiteDatabaseO0 = c3874j2.O0();
                    String[] strArr = {strC};
                    int iDelete = sQLiteDatabaseO0.delete("events", "app_id=?", strArr) + sQLiteDatabaseO0.delete("user_attributes", "app_id=?", strArr) + sQLiteDatabaseO0.delete("conditional_properties", "app_id=?", strArr) + sQLiteDatabaseO0.delete("apps", "app_id=?", strArr) + sQLiteDatabaseO0.delete("raw_events", "app_id=?", strArr) + sQLiteDatabaseO0.delete("raw_events_metadata", "app_id=?", strArr) + sQLiteDatabaseO0.delete("event_filters", "app_id=?", strArr) + sQLiteDatabaseO0.delete("property_filters", "app_id=?", strArr) + sQLiteDatabaseO0.delete("audience_filter_values", "app_id=?", strArr) + sQLiteDatabaseO0.delete("consent_settings", "app_id=?", strArr) + sQLiteDatabaseO0.delete("default_event_params", "app_id=?", strArr) + sQLiteDatabaseO0.delete("trigger_uris", "app_id=?", strArr);
                    if (iDelete > 0) {
                        I i = y.i;
                        Y.k(i);
                        i.o.h("Deleted application data. app, records", strC, Integer.valueOf(iDelete));
                    }
                } catch (SQLiteException e) {
                    I i2 = y.i;
                    Y.k(i2);
                    i2.g.h("Error deleting application data. appId, error", I.a0(strC), e);
                }
                fP0 = null;
            }
        }
        if (fP0 != null) {
            boolean z = (fP0.S() == -2147483648L || fP0.S() == zzrVar.j) ? false : true;
            String strE = fP0.e();
            if (z || ((fP0.S() != -2147483648L || strE == null || strE.equals(zzrVar.c)) ? false : true)) {
                Bundle bundle = new Bundle();
                bundle.putString("_pv", strE);
                zzbh zzbhVar = new zzbh("_au", new zzbf(bundle), "auto", j);
                if (h0().f0(null, AbstractC3893t.m1)) {
                    s(zzbhVar, zzrVar);
                } else {
                    q(zzbhVar, zzrVar);
                }
            }
        }
    }

    public final C3881m0 n0(String str) {
        C3881m0 c3881m0 = C3881m0.c;
        Z.l(this);
        HashMap map = this.B;
        C3881m0 c3881m0W0 = (C3881m0) map.get(str);
        if (c3881m0W0 == null) {
            C3874j c3874j = this.c;
            L(c3874j);
            c3881m0W0 = c3874j.W0(str);
            if (c3881m0W0 == null) {
                c3881m0W0 = C3881m0.c;
            }
            i().S();
            k();
            map.put(str, c3881m0W0);
            C3874j c3874j2 = this.c;
            L(c3874j2);
            c3874j2.q0(str, c3881m0W0);
        }
        return c3881m0W0;
    }

    public final void o(F f, C2969b1 c2969b1) {
        androidx.webkit.internal.p pVar;
        C3019l1 c3019l1;
        EnumC3866f enumC3866f;
        Z.l(this);
        String strV = ((C2974c1) c2969b1.b).v();
        EnumMap enumMap = new EnumMap(EnumC3879l0.class);
        int length = strV.length();
        int length2 = EnumC3879l0.values().length;
        EnumC3866f enumC3866f2 = EnumC3866f.b;
        int i = 0;
        if (length < length2 || strV.charAt(0) != '1') {
            pVar = new androidx.webkit.internal.p(19);
        } else {
            EnumC3879l0[] enumC3879l0ArrValues = EnumC3879l0.values();
            int length3 = enumC3879l0ArrValues.length;
            int i2 = 0;
            int i3 = 1;
            while (i2 < length3) {
                EnumC3879l0 enumC3879l0 = enumC3879l0ArrValues[i2];
                int i4 = i3 + 1;
                char cCharAt = strV.charAt(i3);
                EnumC3866f[] enumC3866fArrValues = EnumC3866f.values();
                int length4 = enumC3866fArrValues.length;
                int i5 = i;
                while (true) {
                    if (i5 >= length4) {
                        enumC3866f = enumC3866f2;
                        break;
                    }
                    enumC3866f = enumC3866fArrValues[i5];
                    if (enumC3866f.a == cCharAt) {
                        break;
                    } else {
                        i5++;
                    }
                }
                enumMap.put((EnumMap) enumC3879l0, (EnumC3879l0) enumC3866f);
                i2++;
                i3 = i4;
                i = 0;
            }
            pVar = new androidx.webkit.internal.p(enumMap);
        }
        String strC = f.c();
        i().S();
        k();
        C3881m0 c3881m0N0 = n0(strC);
        EnumC3879l0 enumC3879l02 = EnumC3879l0.AD_STORAGE;
        EnumMap enumMap2 = c3881m0N0.a;
        EnumC3875j0 enumC3875j0 = (EnumC3875j0) enumMap2.get(enumC3879l02);
        EnumC3875j0 enumC3875j02 = EnumC3875j0.UNINITIALIZED;
        if (enumC3875j0 == null) {
            enumC3875j0 = enumC3875j02;
        }
        int iOrdinal = enumC3875j0.ordinal();
        EnumC3866f enumC3866f3 = EnumC3866f.i;
        EnumC3866f enumC3866f4 = EnumC3866f.j;
        int i6 = c3881m0N0.b;
        if (iOrdinal == 1) {
            pVar.z(enumC3879l02, enumC3866f3);
        } else if (iOrdinal == 2 || iOrdinal == 3) {
            pVar.y(enumC3879l02, i6);
        } else {
            pVar.z(enumC3879l02, enumC3866f4);
        }
        EnumC3879l0 enumC3879l03 = EnumC3879l0.ANALYTICS_STORAGE;
        EnumC3875j0 enumC3875j03 = (EnumC3875j0) enumMap2.get(enumC3879l03);
        if (enumC3875j03 != null) {
            enumC3875j02 = enumC3875j03;
        }
        int iOrdinal2 = enumC3875j02.ordinal();
        if (iOrdinal2 == 1) {
            pVar.z(enumC3879l03, enumC3866f3);
        } else if (iOrdinal2 == 2 || iOrdinal2 == 3) {
            pVar.y(enumC3879l03, i6);
        } else {
            pVar.z(enumC3879l03, enumC3866f4);
        }
        String strC2 = f.c();
        i().S();
        k();
        C3878l c3878lJ0 = j0(strC2, k0(strC2), n0(strC2), pVar);
        Boolean bool = c3878lJ0.c;
        com.google.android.gms.common.internal.u.h(bool);
        boolean zBooleanValue = bool.booleanValue();
        c2969b1.h();
        C2974c1.m0((C2974c1) c2969b1.b, zBooleanValue);
        String str = c3878lJ0.d;
        if (!TextUtils.isEmpty(str)) {
            c2969b1.h();
            C2974c1.X((C2974c1) c2969b1.b, str);
        }
        Z.l(this);
        Iterator it2 = Collections.unmodifiableList(((C2974c1) c2969b1.b).K()).iterator();
        while (true) {
            if (it2.hasNext()) {
                c3019l1 = (C3019l1) it2.next();
                if ("_npa".equals(c3019l1.s())) {
                    break;
                }
            } else {
                c3019l1 = null;
                break;
            }
        }
        if (c3019l1 != null) {
            EnumC3879l0 enumC3879l04 = EnumC3879l0.AD_PERSONALIZATION;
            EnumC3866f enumC3866f5 = (EnumC3866f) ((EnumMap) pVar.b).get(enumC3879l04);
            if (enumC3866f5 == null) {
                enumC3866f5 = enumC3866f2;
            }
            if (enumC3866f5 == enumC3866f2) {
                C3874j c3874j = this.c;
                L(c3874j);
                v1 v1VarY0 = c3874j.Y0(f.c(), "_npa");
                EnumC3866f enumC3866f6 = EnumC3866f.e;
                EnumC3866f enumC3866f7 = EnumC3866f.g;
                if (v1VarY0 != null) {
                    String str2 = v1VarY0.b;
                    if ("tcf".equals(str2)) {
                        pVar.z(enumC3879l04, EnumC3866f.h);
                    } else if ("app".equals(str2)) {
                        pVar.z(enumC3879l04, enumC3866f7);
                    } else {
                        pVar.z(enumC3879l04, enumC3866f6);
                    }
                } else {
                    Boolean boolU = f.U();
                    if (boolU == null || ((boolU.booleanValue() && c3019l1.p() != 1) || !(boolU.booleanValue() || c3019l1.p() == 0))) {
                        pVar.z(enumC3879l04, enumC3866f7);
                    } else {
                        pVar.z(enumC3879l04, enumC3866f6);
                    }
                }
            }
        } else {
            int iY = y(f.c(), pVar);
            C3014k1 c3014k1R = C3019l1.r();
            c3014k1R.h();
            C3019l1.z((C3019l1) c3014k1R.b, "_npa");
            ((com.google.android.gms.common.util.b) f()).getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            c3014k1R.h();
            C3019l1.A((C3019l1) c3014k1R.b, jCurrentTimeMillis);
            c3014k1R.h();
            C3019l1.y((C3019l1) c3014k1R.b, iY);
            C3019l1 c3019l12 = (C3019l1) c3014k1R.f();
            c2969b1.h();
            C2974c1.r0((C2974c1) c2969b1.b, c3019l12);
            c().o.h("Setting user property", "non_personalized_ads(_npa)", Integer.valueOf(iY));
        }
        String string = pVar.toString();
        c2969b1.h();
        C2974c1.V((C2974c1) c2969b1.b, string);
        String strC3 = f.c();
        T t = this.a;
        t.S();
        t.a0(strC3);
        C3087z0 c3087z0G0 = t.g0(strC3);
        boolean z = c3087z0G0 == null || !c3087z0G0.t() || c3087z0G0.s();
        List listA = c2969b1.A();
        for (int i7 = 0; i7 < listA.size(); i7++) {
            if ("_tcf".equals(((com.google.android.gms.internal.measurement.U0) listA.get(i7)).t())) {
                com.google.android.gms.internal.measurement.T0 t0 = (com.google.android.gms.internal.measurement.T0) ((com.google.android.gms.internal.measurement.U0) listA.get(i7)).f();
                List listP = t0.p();
                int i8 = 0;
                while (true) {
                    if (i8 >= listP.size()) {
                        break;
                    }
                    if ("_tcfd".equals(((com.google.android.gms.internal.measurement.X0) listP.get(i8)).s())) {
                        String strT = ((com.google.android.gms.internal.measurement.X0) listP.get(i8)).t();
                        if (z && strT.length() > 4) {
                            char[] charArray = strT.toCharArray();
                            int i9 = 1;
                            while (true) {
                                if (i9 >= 64) {
                                    i9 = 0;
                                    break;
                                } else if (charArray[4] == "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_".charAt(i9)) {
                                    break;
                                } else {
                                    i9++;
                                }
                            }
                            charArray[4] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_".charAt(i9 | 1);
                            strT = String.valueOf(charArray);
                        }
                        com.google.android.gms.internal.measurement.W0 w0R = com.google.android.gms.internal.measurement.X0.r();
                        w0R.k("_tcfd");
                        w0R.l(strT);
                        t0.h();
                        com.google.android.gms.internal.measurement.U0.A((com.google.android.gms.internal.measurement.U0) t0.b, i8, (com.google.android.gms.internal.measurement.X0) w0R.f());
                    } else {
                        i8++;
                    }
                }
                c2969b1.D(i7, t0);
                return;
            }
        }
    }

    public final void p(C2969b1 c2969b1, androidx.work.impl.background.greedy.d dVar) {
        String strA0;
        String strA02;
        for (int i = 0; i < c2969b1.T(); i++) {
            com.google.android.gms.internal.measurement.T0 t0 = (com.google.android.gms.internal.measurement.T0) ((C2974c1) c2969b1.b).j2(i).f();
            Iterator it2 = t0.p().iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                if ("_c".equals(((com.google.android.gms.internal.measurement.X0) it2.next()).s())) {
                    if (((C2974c1) dVar.b).M() >= h0().Y(((C2974c1) dVar.b).r(), AbstractC3893t.k0)) {
                        int iY = h0().Y(((C2974c1) dVar.b).r(), AbstractC3893t.x0);
                        LinkedList linkedList = this.q;
                        M m = this.g;
                        if (iY > 0) {
                            C3874j c3874j = this.c;
                            L(c3874j);
                            if (c3874j.S0(v(), ((C2974c1) dVar.b).r(), false, false, false, true).g > iY) {
                                com.google.android.gms.internal.measurement.W0 w0R = com.google.android.gms.internal.measurement.X0.r();
                                w0R.k("_tnr");
                                w0R.i(1L);
                                t0.m((com.google.android.gms.internal.measurement.X0) w0R.f());
                            } else {
                                if (h0().f0(((C2974c1) dVar.b).r(), AbstractC3893t.X0)) {
                                    strA02 = e().a0();
                                    com.google.android.gms.internal.measurement.W0 w0R2 = com.google.android.gms.internal.measurement.X0.r();
                                    w0R2.k("_tu");
                                    w0R2.l(strA02);
                                    t0.m((com.google.android.gms.internal.measurement.X0) w0R2.f());
                                } else {
                                    strA02 = null;
                                }
                                com.google.android.gms.internal.measurement.W0 w0R3 = com.google.android.gms.internal.measurement.X0.r();
                                w0R3.k("_tr");
                                w0R3.i(1L);
                                t0.m((com.google.android.gms.internal.measurement.X0) w0R3.f());
                                L(m);
                                zzov zzovVarW0 = m.w0(((C2974c1) dVar.b).r(), c2969b1, t0, strA02);
                                if (zzovVarW0 != null) {
                                    c().o.h("Generated trigger URI. appId, uri", ((C2974c1) dVar.b).r(), zzovVarW0.a);
                                    C3874j c3874j2 = this.c;
                                    L(c3874j2);
                                    c3874j2.C0(((C2974c1) dVar.b).r(), zzovVarW0);
                                    if (!linkedList.contains(((C2974c1) dVar.b).r())) {
                                        linkedList.add(((C2974c1) dVar.b).r());
                                    }
                                }
                            }
                        } else {
                            if (h0().f0(((C2974c1) dVar.b).r(), AbstractC3893t.X0)) {
                                strA0 = e().a0();
                                com.google.android.gms.internal.measurement.W0 w0R4 = com.google.android.gms.internal.measurement.X0.r();
                                w0R4.k("_tu");
                                w0R4.l(strA0);
                                t0.m((com.google.android.gms.internal.measurement.X0) w0R4.f());
                            } else {
                                strA0 = null;
                            }
                            com.google.android.gms.internal.measurement.W0 w0R5 = com.google.android.gms.internal.measurement.X0.r();
                            w0R5.k("_tr");
                            w0R5.i(1L);
                            t0.m((com.google.android.gms.internal.measurement.X0) w0R5.f());
                            L(m);
                            zzov zzovVarW02 = m.w0(((C2974c1) dVar.b).r(), c2969b1, t0, strA0);
                            if (zzovVarW02 != null) {
                                c().o.h("Generated trigger URI. appId, uri", ((C2974c1) dVar.b).r(), zzovVarW02.a);
                                C3874j c3874j3 = this.c;
                                L(c3874j3);
                                c3874j3.C0(((C2974c1) dVar.b).r(), zzovVarW02);
                                if (!linkedList.contains(((C2974c1) dVar.b).r())) {
                                    linkedList.add(((C2974c1) dVar.b).r());
                                }
                            }
                        }
                    }
                    com.google.android.gms.internal.measurement.U0 u0 = (com.google.android.gms.internal.measurement.U0) t0.f();
                    c2969b1.h();
                    C2974c1.g0((C2974c1) c2969b1.b, i, u0);
                }
            }
        }
    }

    public final void q(zzbh zzbhVar, zzr zzrVar) {
        List listY;
        Y y;
        List listY2;
        List<zzai> listY3;
        String str;
        com.google.android.gms.common.internal.u.h(zzrVar);
        String str2 = zzrVar.a;
        com.google.android.gms.common.internal.u.e(str2);
        i().S();
        k();
        J jK = J.k(zzbhVar);
        i().S();
        x1.h0((this.F == null || (str = this.G) == null || !str.equals(str2)) ? null : this.F, (Bundle) jK.e, false);
        zzbh zzbhVarJ = jK.j();
        a();
        if (TextUtils.isEmpty(zzrVar.b) && TextUtils.isEmpty(zzrVar.p)) {
            return;
        }
        if (!zzrVar.h) {
            f0(zzrVar);
            return;
        }
        List list = zzrVar.s;
        if (list != null) {
            String str3 = zzbhVarJ.a;
            if (!list.contains(str3)) {
                c().n.i("Dropping non-safelisted event. appId, event name, origin", str2, zzbhVarJ.a, zzbhVarJ.c);
                return;
            } else {
                Bundle bundleA = zzbhVarJ.b.a();
                bundleA.putLong("ga_safelisted", 1L);
                zzbhVarJ = new zzbh(str3, new zzbf(bundleA), zzbhVarJ.c, zzbhVarJ.d);
            }
        }
        C3874j c3874j = this.c;
        L(c3874j);
        c3874j.d0();
        try {
            boolean zF0 = h0().f0(null, AbstractC3893t.i1);
            String str4 = zzbhVarJ.a;
            if (zF0 && "_s".equals(str4)) {
                C3874j c3874j2 = this.c;
                L(c3874j2);
                if (!c3874j2.s0(str2, "_s") && zzbhVarJ.b.a.getLong("_sid") != 0) {
                    C3874j c3874j3 = this.c;
                    L(c3874j3);
                    if (c3874j3.s0(str2, "_f")) {
                        C3874j c3874j4 = this.c;
                        L(c3874j4);
                        c3874j4.c0(str2, null, "_sid", e0(zzbhVarJ, str2));
                    } else {
                        C3874j c3874j5 = this.c;
                        L(c3874j5);
                        if (c3874j5.s0(str2, "_v")) {
                            C3874j c3874j42 = this.c;
                            L(c3874j42);
                            c3874j42.c0(str2, null, "_sid", e0(zzbhVarJ, str2));
                        } else {
                            C3874j c3874j6 = this.c;
                            L(c3874j6);
                            ((com.google.android.gms.common.util.b) f()).getClass();
                            c3874j6.c0(str2, Long.valueOf(System.currentTimeMillis() - 15000), "_sid", e0(zzbhVarJ, str2));
                        }
                    }
                }
            }
            C3874j c3874j7 = this.c;
            L(c3874j7);
            com.google.android.gms.common.internal.u.e(str2);
            c3874j7.S();
            c3874j7.T();
            long j = zzbhVar.d;
            if (j < 0) {
                I i = ((Y) c3874j7.b).i;
                Y.k(i);
                i.j.h("Invalid time querying timed out conditional properties", I.a0(str2), Long.valueOf(j));
                listY = Collections.EMPTY_LIST;
            } else {
                listY = c3874j7.Y("active=0 and app_id=? and abs(? - creation_timestamp) > trigger_timeout", new String[]{str2, String.valueOf(j)});
            }
            Iterator it2 = listY.iterator();
            while (true) {
                boolean zHasNext = it2.hasNext();
                y = this.l;
                if (!zHasNext) {
                    break;
                }
                zzai zzaiVar = (zzai) it2.next();
                if (zzaiVar != null) {
                    c().o.i("User property timed out", zzaiVar.a, y.m.f(zzaiVar.c.b), zzaiVar.c.a());
                    zzbh zzbhVar2 = zzaiVar.g;
                    if (zzbhVar2 != null) {
                        b0(new zzbh(zzbhVar2, j), zzrVar);
                    }
                    C3874j c3874j8 = this.c;
                    L(c3874j8);
                    c3874j8.t0(str2, zzaiVar.c.b);
                }
            }
            C3874j c3874j9 = this.c;
            L(c3874j9);
            com.google.android.gms.common.internal.u.e(str2);
            c3874j9.S();
            c3874j9.T();
            if (j < 0) {
                I i2 = ((Y) c3874j9.b).i;
                Y.k(i2);
                i2.j.h("Invalid time querying expired conditional properties", I.a0(str2), Long.valueOf(j));
                listY2 = Collections.EMPTY_LIST;
            } else {
                listY2 = c3874j9.Y("active<>0 and app_id=? and abs(? - triggered_timestamp) > time_to_live", new String[]{str2, String.valueOf(j)});
            }
            ArrayList arrayList = new ArrayList(listY2.size());
            Iterator it3 = listY2.iterator();
            while (it3.hasNext()) {
                zzai zzaiVar2 = (zzai) it3.next();
                if (zzaiVar2 != null) {
                    Iterator it4 = it3;
                    c().o.i("User property expired", zzaiVar2.a, y.m.f(zzaiVar2.c.b), zzaiVar2.c.a());
                    C3874j c3874j10 = this.c;
                    L(c3874j10);
                    c3874j10.l0(str2, zzaiVar2.c.b);
                    zzbh zzbhVar3 = zzaiVar2.k;
                    if (zzbhVar3 != null) {
                        arrayList.add(zzbhVar3);
                    }
                    C3874j c3874j11 = this.c;
                    L(c3874j11);
                    c3874j11.t0(str2, zzaiVar2.c.b);
                    it3 = it4;
                }
            }
            Iterator it5 = arrayList.iterator();
            while (it5.hasNext()) {
                b0(new zzbh((zzbh) it5.next(), j), zzrVar);
            }
            C3874j c3874j12 = this.c;
            L(c3874j12);
            com.google.android.gms.common.internal.u.e(str2);
            com.google.android.gms.common.internal.u.e(str4);
            c3874j12.S();
            c3874j12.T();
            if (j < 0) {
                Y y2 = (Y) c3874j12.b;
                I i3 = y2.i;
                Y.k(i3);
                i3.j.i("Invalid time querying triggered conditional properties", I.a0(str2), y2.m.d(str4), Long.valueOf(j));
                listY3 = Collections.EMPTY_LIST;
            } else {
                listY3 = c3874j12.Y("active=0 and app_id=? and trigger_event_name=? and abs(? - creation_timestamp) <= trigger_timeout", new String[]{str2, str4, String.valueOf(j)});
            }
            ArrayList arrayList2 = new ArrayList(listY3.size());
            for (zzai zzaiVar3 : listY3) {
                if (zzaiVar3 != null) {
                    zzqb zzqbVar = zzaiVar3.c;
                    String str5 = zzaiVar3.a;
                    com.google.android.gms.common.internal.u.h(str5);
                    String str6 = zzaiVar3.b;
                    String str7 = zzqbVar.b;
                    Object objA = zzqbVar.a();
                    com.google.android.gms.common.internal.u.h(objA);
                    long j2 = j;
                    v1 v1Var = new v1(str5, str6, str7, j2, objA);
                    j = j2;
                    Object obj = v1Var.e;
                    String str8 = v1Var.c;
                    C3874j c3874j13 = this.c;
                    L(c3874j13);
                    if (c3874j13.G0(v1Var)) {
                        c().o.i("User property triggered", zzaiVar3.a, y.m.f(str8), obj);
                    } else {
                        c().g.i("Too many active user properties, ignoring", I.a0(zzaiVar3.a), y.m.f(str8), obj);
                    }
                    zzbh zzbhVar4 = zzaiVar3.i;
                    if (zzbhVar4 != null) {
                        arrayList2.add(zzbhVar4);
                    }
                    zzaiVar3.c = new zzqb(v1Var);
                    zzaiVar3.e = true;
                    C3874j c3874j14 = this.c;
                    L(c3874j14);
                    c3874j14.F0(zzaiVar3);
                }
            }
            b0(zzbhVarJ, zzrVar);
            Iterator it6 = arrayList2.iterator();
            while (it6.hasNext()) {
                b0(new zzbh((zzbh) it6.next(), j), zzrVar);
            }
            C3874j c3874j15 = this.c;
            L(c3874j15);
            c3874j15.n0();
            C3874j c3874j16 = this.c;
            L(c3874j16);
            c3874j16.h0();
        } catch (Throwable th) {
            C3874j c3874j17 = this.c;
            L(c3874j17);
            c3874j17.h0();
            throw th;
        }
    }

    public final void r(zzbh zzbhVar, String str) {
        C3874j c3874j = this.c;
        L(c3874j);
        F fP0 = c3874j.P0(str);
        if (fP0 == null || TextUtils.isEmpty(fP0.e())) {
            c().n.g("No app data available; dropping event", str);
            return;
        }
        Boolean boolA = A(fP0);
        if (boolA == null) {
            if (!"_ui".equals(zzbhVar.a)) {
                I iC = c();
                iC.j.g("Could not find package. appId", I.a0(str));
            }
        } else if (!boolA.booleanValue()) {
            I iC2 = c();
            iC2.g.g("App version does not match; dropping event. appId", I.a0(str));
            return;
        }
        String strG = fP0.g();
        String strE = fP0.e();
        long jS = fP0.S();
        Y y = fP0.a;
        X x = y.j;
        Y.k(x);
        x.S();
        String str2 = fP0.l;
        X x2 = y.j;
        Y.k(x2);
        x2.S();
        long j = fP0.m;
        X x3 = y.j;
        Y.k(x3);
        x3.S();
        long j2 = fP0.n;
        X x4 = y.j;
        Y.k(x4);
        x4.S();
        boolean z = fP0.o;
        String strF = fP0.f();
        X x5 = y.j;
        Y.k(x5);
        x5.S();
        boolean z2 = fP0.p;
        String strA = fP0.a();
        Boolean boolU = fP0.U();
        long jT = fP0.T();
        X x6 = y.j;
        Y.k(x6);
        x6.S();
        ArrayList arrayList = fP0.t;
        String strJ = n0(str).j();
        boolean zT = fP0.t();
        X x7 = y.j;
        Y.k(x7);
        x7.S();
        long j3 = fP0.w;
        C3881m0 c3881m0N0 = n0(str);
        String str3 = k0(str).b;
        X x8 = y.j;
        Y.k(x8);
        x8.S();
        int i = fP0.y;
        X x9 = y.j;
        Y.k(x9);
        x9.S();
        s(zzbhVar, new zzr(str, strG, strE, jS, str2, j, j2, (String) null, z, false, strF, 0L, 0, z2, false, strA, boolU, jT, (List) arrayList, (String) null, strJ, "", (String) null, zT, j3, c3881m0N0.b, str3, i, fP0.C, fP0.i(), fP0.h(), 0L, fP0.R()));
    }

    /* JADX WARN: Not initialized variable reg: 5, insn: 0x007b: MOVE (r4 I:??[OBJECT, ARRAY]) = (r5 I:??[OBJECT, ARRAY]), block:B:18:0x007b */
    /* JADX WARN: Removed duplicated region for block: B:14:0x0065 A[PHI: r4 r5
  0x0065: PHI (r4v3 android.os.Bundle) = (r4v7 android.os.Bundle), (r4v5 android.os.Bundle) binds: [B:24:0x0090, B:13:0x0058] A[DONT_GENERATE, DONT_INLINE]
  0x0065: PHI (r5v3 android.database.Cursor) = (r5v5 android.database.Cursor), (r5v7 android.database.Cursor) binds: [B:24:0x0090, B:13:0x0058] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00c9  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00fd  */
    /* JADX WARN: Removed duplicated region for block: B:44:? A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void s(com.google.android.gms.measurement.internal.zzbh r10, com.google.android.gms.measurement.internal.zzr r11) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 257
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.s(com.google.android.gms.measurement.internal.zzbh, com.google.android.gms.measurement.internal.zzr):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x004b  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x016e A[Catch: all -> 0x005f, TryCatch #1 {all -> 0x005f, blocks: (B:8:0x0030, B:18:0x004e, B:57:0x0171, B:26:0x006c, B:31:0x00ce, B:30:0x00ba, B:32:0x00d3, B:36:0x00e4, B:40:0x00fa, B:42:0x0114, B:44:0x012f, B:46:0x0138, B:48:0x013e, B:49:0x0142, B:51:0x014e, B:53:0x0157, B:55:0x0166, B:56:0x016e, B:43:0x0120, B:37:0x00eb, B:39:0x00f4), top: B:66:0x0030, outer: #0 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void t(java.lang.String r10, int r11, java.io.IOException r12, byte[] r13, java.util.Map r14) {
        /*
            Method dump skipped, instructions count: 406
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.t(java.lang.String, int, java.io.IOException, byte[], java.util.Map):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:101:0x026f A[Catch: all -> 0x000f, SQLiteException -> 0x00b4, TryCatch #2 {SQLiteException -> 0x00b4, blocks: (B:24:0x009f, B:27:0x00b7, B:29:0x00c5, B:31:0x00e1, B:93:0x023f, B:96:0x0257, B:98:0x0260, B:100:0x026b, B:107:0x0287, B:101:0x026f, B:103:0x0278, B:105:0x027e, B:106:0x0282, B:108:0x028a, B:109:0x0292, B:30:0x00d6), top: B:119:0x009f, outer: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:20:0x0069 A[Catch: all -> 0x000f, TryCatch #4 {all -> 0x000f, blocks: (B:4:0x000c, B:8:0x0014, B:16:0x0029, B:21:0x007d, B:20:0x0069, B:22:0x008a, B:24:0x009f, B:27:0x00b7, B:29:0x00c5, B:31:0x00e1, B:93:0x023f, B:96:0x0257, B:98:0x0260, B:100:0x026b, B:107:0x0287, B:101:0x026f, B:103:0x0278, B:105:0x027e, B:106:0x0282, B:108:0x028a, B:109:0x0292, B:30:0x00d6, B:110:0x0293), top: B:121:0x000c, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:22:0x008a A[Catch: all -> 0x000f, PHI: r0
  0x008a: PHI (r0v2 int) = (r0v0 int), (r0v35 int) binds: [B:9:0x001c, B:15:0x0027] A[DONT_GENERATE, DONT_INLINE], TRY_LEAVE, TryCatch #4 {all -> 0x000f, blocks: (B:4:0x000c, B:8:0x0014, B:16:0x0029, B:21:0x007d, B:20:0x0069, B:22:0x008a, B:24:0x009f, B:27:0x00b7, B:29:0x00c5, B:31:0x00e1, B:93:0x023f, B:96:0x0257, B:98:0x0260, B:100:0x026b, B:107:0x0287, B:101:0x026f, B:103:0x0278, B:105:0x027e, B:106:0x0282, B:108:0x028a, B:109:0x0292, B:30:0x00d6, B:110:0x0293), top: B:121:0x000c, inners: #2 }] */
    /* JADX WARN: Removed duplicated region for block: B:29:0x00c5 A[Catch: all -> 0x000f, SQLiteException -> 0x00b4, TryCatch #2 {SQLiteException -> 0x00b4, blocks: (B:24:0x009f, B:27:0x00b7, B:29:0x00c5, B:31:0x00e1, B:93:0x023f, B:96:0x0257, B:98:0x0260, B:100:0x026b, B:107:0x0287, B:101:0x026f, B:103:0x0278, B:105:0x027e, B:106:0x0282, B:108:0x028a, B:109:0x0292, B:30:0x00d6), top: B:119:0x009f, outer: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:30:0x00d6 A[Catch: all -> 0x000f, SQLiteException -> 0x00b4, TryCatch #2 {SQLiteException -> 0x00b4, blocks: (B:24:0x009f, B:27:0x00b7, B:29:0x00c5, B:31:0x00e1, B:93:0x023f, B:96:0x0257, B:98:0x0260, B:100:0x026b, B:107:0x0287, B:101:0x026f, B:103:0x0278, B:105:0x027e, B:106:0x0282, B:108:0x028a, B:109:0x0292, B:30:0x00d6), top: B:119:0x009f, outer: #4 }] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00f7 A[Catch: all -> 0x015b, TryCatch #3 {all -> 0x015b, blocks: (B:32:0x00e9, B:34:0x00f7, B:36:0x0103, B:37:0x010c, B:40:0x0114, B:42:0x0126, B:44:0x0131, B:46:0x0139, B:50:0x0145, B:52:0x014f, B:55:0x015e, B:56:0x0162, B:58:0x0168, B:60:0x017a, B:62:0x0191, B:63:0x0193, B:65:0x01a8, B:66:0x01ac, B:68:0x01b2, B:70:0x01cc, B:71:0x01ce, B:72:0x01d8, B:73:0x01dc, B:75:0x01e2, B:76:0x01e9, B:77:0x0204, B:80:0x0210, B:81:0x0217, B:83:0x0219, B:84:0x0229, B:86:0x022b, B:88:0x022f, B:91:0x0236, B:92:0x0237), top: B:120:0x00e9, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01e2 A[Catch: all -> 0x015b, TRY_LEAVE, TryCatch #3 {all -> 0x015b, blocks: (B:32:0x00e9, B:34:0x00f7, B:36:0x0103, B:37:0x010c, B:40:0x0114, B:42:0x0126, B:44:0x0131, B:46:0x0139, B:50:0x0145, B:52:0x014f, B:55:0x015e, B:56:0x0162, B:58:0x0168, B:60:0x017a, B:62:0x0191, B:63:0x0193, B:65:0x01a8, B:66:0x01ac, B:68:0x01b2, B:70:0x01cc, B:71:0x01ce, B:72:0x01d8, B:73:0x01dc, B:75:0x01e2, B:76:0x01e9, B:77:0x0204, B:80:0x0210, B:81:0x0217, B:83:0x0219, B:84:0x0229, B:86:0x022b, B:88:0x022f, B:91:0x0236, B:92:0x0237), top: B:120:0x00e9, inners: #1 }] */
    /* JADX WARN: Removed duplicated region for block: B:96:0x0257 A[Catch: all -> 0x000f, SQLiteException -> 0x00b4, TRY_ENTER, TryCatch #2 {SQLiteException -> 0x00b4, blocks: (B:24:0x009f, B:27:0x00b7, B:29:0x00c5, B:31:0x00e1, B:93:0x023f, B:96:0x0257, B:98:0x0260, B:100:0x026b, B:107:0x0287, B:101:0x026f, B:103:0x0278, B:105:0x027e, B:106:0x0282, B:108:0x028a, B:109:0x0292, B:30:0x00d6), top: B:119:0x009f, outer: #4 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void u(boolean r19, int r20, java.io.IOException r21, byte[] r22, java.lang.String r23, java.util.List r24) {
        /*
            Method dump skipped, instructions count: 714
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.u(boolean, int, java.io.IOException, byte[], java.lang.String, java.util.List):void");
    }

    public final long v() {
        ((com.google.android.gms.common.util.b) f()).getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        a1 a1Var = this.i;
        a1Var.T();
        a1Var.S();
        N n = a1Var.k;
        long jA = n.a();
        if (jA == 0) {
            Y.h(((Y) a1Var.b).l);
            jA = r2.d0().nextInt(86400000) + 1;
            n.b(jA);
        }
        return ((((jCurrentTimeMillis + jA) / 1000) / 60) / 60) / 24;
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x003e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int y(java.lang.String r6, androidx.webkit.internal.p r7) {
        /*
            r5 = this;
            com.google.android.gms.measurement.internal.T r0 = r5.a
            com.google.android.gms.internal.measurement.z0 r1 = r0.g0(r6)
            com.google.android.gms.measurement.internal.l0 r2 = com.google.android.gms.measurement.internal.EnumC3879l0.AD_PERSONALIZATION
            r3 = 1
            if (r1 != 0) goto L11
            com.google.android.gms.measurement.internal.f r6 = com.google.android.gms.measurement.internal.EnumC3866f.j
            r7.z(r2, r6)
            return r3
        L11:
            com.google.android.gms.measurement.internal.j r1 = r5.c
            L(r1)
            com.google.android.gms.measurement.internal.F r1 = r1.P0(r6)
            if (r1 == 0) goto L3e
            java.lang.String r1 = r1.h()
            com.airbnb.lottie.network.c r1 = com.airbnb.lottie.network.c.B(r1)
            com.google.android.gms.measurement.internal.j0 r4 = com.google.android.gms.measurement.internal.EnumC3875j0.POLICY
            java.lang.Object r1 = r1.b
            com.google.android.gms.measurement.internal.j0 r1 = (com.google.android.gms.measurement.internal.EnumC3875j0) r1
            if (r1 != r4) goto L3e
            com.google.android.gms.measurement.internal.j0 r1 = r0.f0(r6, r2)
            com.google.android.gms.measurement.internal.j0 r4 = com.google.android.gms.measurement.internal.EnumC3875j0.UNINITIALIZED
            if (r1 == r4) goto L3e
            com.google.android.gms.measurement.internal.f r6 = com.google.android.gms.measurement.internal.EnumC3866f.i
            r7.z(r2, r6)
            com.google.android.gms.measurement.internal.j0 r6 = com.google.android.gms.measurement.internal.EnumC3875j0.GRANTED
            if (r1 != r6) goto L4b
            goto L49
        L3e:
            com.google.android.gms.measurement.internal.f r1 = com.google.android.gms.measurement.internal.EnumC3866f.c
            r7.z(r2, r1)
            boolean r6 = r0.j0(r6, r2)
            if (r6 == 0) goto L4b
        L49:
            r6 = 0
            return r6
        L4b:
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.r1.y(java.lang.String, androidx.webkit.internal.p):int");
    }

    public final zzr z(String str) {
        C3874j c3874j = this.c;
        L(c3874j);
        F fP0 = c3874j.P0(str);
        if (fP0 == null || TextUtils.isEmpty(fP0.e())) {
            c().n.g("No app data available; dropping", str);
            return null;
        }
        Boolean boolA = A(fP0);
        if (boolA != null && !boolA.booleanValue()) {
            I iC = c();
            iC.g.g("App version does not match; dropping. appId", I.a0(str));
            return null;
        }
        String strG = fP0.g();
        String strE = fP0.e();
        long jS = fP0.S();
        Y y = fP0.a;
        X x = y.j;
        Y.k(x);
        x.S();
        String str2 = fP0.l;
        X x2 = y.j;
        Y.k(x2);
        x2.S();
        long j = fP0.m;
        X x3 = y.j;
        Y.k(x3);
        x3.S();
        long j2 = fP0.n;
        X x4 = y.j;
        Y.k(x4);
        x4.S();
        boolean z = fP0.o;
        String strF = fP0.f();
        X x5 = y.j;
        Y.k(x5);
        x5.S();
        boolean z2 = fP0.p;
        String strA = fP0.a();
        Boolean boolU = fP0.U();
        long jT = fP0.T();
        X x6 = y.j;
        Y.k(x6);
        x6.S();
        ArrayList arrayList = fP0.t;
        String strJ = n0(str).j();
        boolean zT = fP0.t();
        X x7 = y.j;
        Y.k(x7);
        x7.S();
        long j3 = fP0.w;
        C3881m0 c3881m0N0 = n0(str);
        String str3 = k0(str).b;
        X x8 = y.j;
        Y.k(x8);
        x8.S();
        int i = fP0.y;
        X x9 = y.j;
        Y.k(x9);
        x9.S();
        return new zzr(str, strG, strE, jS, str2, j, j2, (String) null, z, false, strF, 0L, 0, z2, false, strA, boolU, jT, (List) arrayList, (String) null, strJ, "", (String) null, zT, j3, c3881m0N0.b, str3, i, fP0.C, fP0.i(), fP0.h(), 0L, fP0.R());
    }
}
