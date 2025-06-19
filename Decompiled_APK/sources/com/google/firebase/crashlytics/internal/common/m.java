package com.google.firebase.crashlytics.internal.common;

import android.content.Context;
import android.content.res.Resources;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import androidx.compose.ui.node.V;
import com.facebook.internal.H;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.measurement.internal.Z;
import com.google.android.gms.tasks.Task;
import com.google.firebase.crashlytics.internal.model.A;
import com.google.firebase.crashlytics.internal.model.B;
import com.google.firebase.crashlytics.internal.model.C3941i0;
import com.google.firebase.crashlytics.internal.model.C3947l0;
import com.google.firebase.crashlytics.internal.model.C3949m0;
import com.google.firebase.crashlytics.internal.model.C3951n0;
import com.google.firebase.crashlytics.internal.model.C3953o0;
import com.google.firebase.crashlytics.internal.model.I;
import com.google.firebase.crashlytics.internal.model.J;
import com.google.firebase.crashlytics.internal.model.K;
import com.google.firebase.crashlytics.internal.model.M;
import com.google.firebase.crashlytics.internal.model.O0;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.NavigableSet;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicMarkableReference;

/* loaded from: classes2.dex */
public final class m {
    public static final H r = new H(6);
    public static final Charset s = Charset.forName("UTF-8");
    public final Context a;
    public final com.quizlet.data.repository.studysetwithcreatorinclass.g b;
    public final com.quizlet.data.repository.activitycenter.b c;
    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.d d;
    public final com.google.firebase.crashlytics.internal.concurrency.d e;
    public final v f;
    public final com.google.firebase.crashlytics.internal.persistence.c g;
    public final V h;
    public final com.google.firebase.crashlytics.internal.metadata.f i;
    public final com.google.firebase.crashlytics.internal.a j;
    public final com.google.firebase.crashlytics.a k;
    public final h l;
    public final com.onetrust.otpublishers.headless.UI.TVUI.datautils.d m;
    public s n;
    public final com.google.android.gms.tasks.f o = new com.google.android.gms.tasks.f();
    public final com.google.android.gms.tasks.f p = new com.google.android.gms.tasks.f();
    public final com.google.android.gms.tasks.f q = new com.google.android.gms.tasks.f();

    public m(Context context, v vVar, com.quizlet.data.repository.studysetwithcreatorinclass.g gVar, com.google.firebase.crashlytics.internal.persistence.c cVar, com.quizlet.data.repository.activitycenter.b bVar, V v, com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar, com.google.firebase.crashlytics.internal.metadata.f fVar, com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar2, com.google.firebase.crashlytics.internal.a aVar, com.google.firebase.crashlytics.a aVar2, h hVar, com.google.firebase.crashlytics.internal.concurrency.d dVar3) {
        new AtomicBoolean(false);
        this.a = context;
        this.f = vVar;
        this.b = gVar;
        this.g = cVar;
        this.c = bVar;
        this.h = v;
        this.d = dVar;
        this.i = fVar;
        this.j = aVar;
        this.k = aVar2;
        this.l = hVar;
        this.m = dVar2;
        this.e = dVar3;
    }

    public static com.google.android.gms.tasks.m a(m mVar) throws NumberFormatException, ClassNotFoundException {
        com.google.android.gms.tasks.m mVarG;
        mVar.getClass();
        ArrayList arrayList = new ArrayList();
        for (File file : com.google.firebase.crashlytics.internal.persistence.c.e(mVar.g.c.listFiles(r))) {
            try {
                long j = Long.parseLong(file.getName().substring(3));
                try {
                    Class.forName("com.google.firebase.crash.FirebaseCrash");
                    Log.w("FirebaseCrashlytics", "Skipping logging Crashlytics event to Firebase, FirebaseCrash exists", null);
                    mVarG = S3.i(null);
                } catch (ClassNotFoundException unused) {
                    Log.isLoggable("FirebaseCrashlytics", 3);
                    mVarG = S3.g(new ScheduledThreadPoolExecutor(1), new l(mVar, j));
                }
                arrayList.add(mVarG);
            } catch (NumberFormatException unused2) {
                Log.w("FirebaseCrashlytics", "Could not parse app exception timestamp from file " + file.getName(), null);
            }
            file.delete();
        }
        return S3.j(arrayList);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:109:0x03a0  */
    /* JADX WARN: Removed duplicated region for block: B:112:0x03db  */
    /* JADX WARN: Removed duplicated region for block: B:114:0x03de  */
    /* JADX WARN: Removed duplicated region for block: B:115:0x03ec  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x0414  */
    /* JADX WARN: Removed duplicated region for block: B:127:0x044e  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x045a A[LOOP:2: B:131:0x045a->B:133:0x0460, LOOP_START] */
    /* JADX WARN: Removed duplicated region for block: B:137:0x0482  */
    /* JADX WARN: Removed duplicated region for block: B:159:0x0502  */
    /* JADX WARN: Removed duplicated region for block: B:233:0x068a  */
    /* JADX WARN: Removed duplicated region for block: B:237:0x06a2 A[ORIG_RETURN, RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:249:0x015f A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:43:0x0137  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x0154  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x028e  */
    /* JADX WARN: Type inference failed for: r11v15 */
    /* JADX WARN: Type inference failed for: r11v16, types: [int] */
    /* JADX WARN: Type inference failed for: r11v42 */
    /* JADX WARN: Type inference failed for: r33v0, types: [boolean] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(boolean r33, com.google.android.datatransport.cct.internal.s r34, boolean r35) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1699
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.crashlytics.internal.common.m.b(boolean, com.google.android.datatransport.cct.internal.s, boolean):void");
    }

    public final void c(String str, Boolean bool) throws IOException {
        long j;
        String str2;
        String str3;
        long j2;
        Integer num;
        Map mapUnmodifiableMap;
        long jCurrentTimeMillis = System.currentTimeMillis() / 1000;
        Log.isLoggable("FirebaseCrashlytics", 3);
        Locale locale = Locale.US;
        v vVar = this.f;
        V v = this.h;
        C3949m0 c3949m0 = new C3949m0(vVar.c, (String) v.g, (String) v.h, vVar.c().a, Z.a(((String) v.e) != null ? 4 : 1), (com.google.firebase.crashlytics.internal.c) v.i);
        String str4 = Build.VERSION.RELEASE;
        String str5 = Build.VERSION.CODENAME;
        C3953o0 c3953o0 = new C3953o0(f.g());
        Context context = this.a;
        StatFs statFs = new StatFs(Environment.getDataDirectory().getPath());
        long blockCount = statFs.getBlockCount() * statFs.getBlockSize();
        e eVar = e.a;
        String str6 = Build.CPU_ABI;
        boolean zIsEmpty = TextUtils.isEmpty(str6);
        e eVar2 = e.a;
        if (zIsEmpty) {
            Log.isLoggable("FirebaseCrashlytics", 2);
            j = 1000;
        } else {
            j = 1000;
            e eVar3 = (e) e.b.get(str6.toLowerCase(locale));
            if (eVar3 != null) {
                eVar2 = eVar3;
            }
        }
        int iOrdinal = eVar2.ordinal();
        String str7 = Build.MODEL;
        int iAvailableProcessors = Runtime.getRuntime().availableProcessors();
        long jA = f.a(context);
        boolean zF = f.f();
        int iC = f.c();
        String str8 = Build.MANUFACTURER;
        String str9 = Build.PRODUCT;
        C3951n0 c3951n0 = new C3951n0(iOrdinal, iAvailableProcessors, jA, blockCount, zF, iC);
        com.google.firebase.crashlytics.internal.a aVar = this.j;
        C3947l0 c3947l0 = new C3947l0(c3949m0, c3953o0, c3951n0);
        aVar.getClass();
        Log.isLoggable("FirebaseCrashlytics", 2);
        String str10 = str;
        aVar.a.a(new androidx.camera.core.impl.utils.futures.e(str10, jCurrentTimeMillis, c3947l0, 3));
        if (!bool.booleanValue() || str10 == null) {
            str2 = str7;
            str3 = str8;
            j2 = jCurrentTimeMillis;
        } else {
            com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = this.d;
            synchronized (((String) dVar.b)) {
                dVar.b = str10;
                com.google.firebase.crashlytics.internal.metadata.e eVar4 = (com.google.firebase.crashlytics.internal.metadata.e) ((AtomicMarkableReference) ((androidx.browser.customtabs.k) dVar.d).b).getReference();
                synchronized (eVar4) {
                    mapUnmodifiableMap = Collections.unmodifiableMap(new HashMap(eVar4.a));
                }
                str2 = str7;
                str3 = str8;
                j2 = jCurrentTimeMillis;
                str10 = str;
                ((com.google.firebase.crashlytics.internal.concurrency.d) dVar.c).b.a(new androidx.camera.camera2.internal.compat.b(dVar, str, mapUnmodifiableMap, ((com.google.firebase.crashlytics.internal.metadata.p) dVar.f).b(), 10));
            }
        }
        com.google.firebase.crashlytics.internal.metadata.f fVar = this.i;
        ((com.google.firebase.crashlytics.internal.metadata.d) fVar.b).a();
        fVar.b = com.google.firebase.crashlytics.internal.metadata.f.c;
        if (str10 != null) {
            fVar.b = new com.google.firebase.crashlytics.internal.metadata.n(((com.google.firebase.crashlytics.internal.persistence.c) fVar.a).b(str10, "userlog"));
        }
        this.l.a(str10);
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar2 = this.m;
        r rVar = (r) dVar2.a;
        Charset charset = O0.a;
        A a = new A();
        a.a = "19.4.3";
        V v2 = rVar.c;
        String str11 = (String) v2.b;
        if (str11 == null) {
            throw new NullPointerException("Null gmpAppId");
        }
        a.b = str11;
        v vVar2 = rVar.b;
        String str12 = vVar2.c().a;
        if (str12 == null) {
            throw new NullPointerException("Null installationUuid");
        }
        a.d = str12;
        a.e = vVar2.c().b;
        a.f = vVar2.c().c;
        String str13 = (String) v2.g;
        if (str13 == null) {
            throw new NullPointerException("Null buildVersion");
        }
        a.h = str13;
        String str14 = (String) v2.h;
        if (str14 == null) {
            throw new NullPointerException("Null displayVersion");
        }
        a.i = str14;
        a.c = 4;
        a.m = (byte) (a.m | 1);
        I i = new I();
        i.f = false;
        byte b = (byte) (i.m | 2);
        i.d = j2;
        i.m = (byte) (b | 1);
        if (str10 == null) {
            throw new NullPointerException("Null identifier");
        }
        i.b = str10;
        String str15 = r.g;
        if (str15 == null) {
            throw new NullPointerException("Null generator");
        }
        i.a = str15;
        String str16 = vVar2.c;
        if (str16 == null) {
            throw new NullPointerException("Null identifier");
        }
        String str17 = vVar2.c().a;
        com.google.firebase.crashlytics.internal.c cVar = (com.google.firebase.crashlytics.internal.c) v2.i;
        if (cVar.b == null) {
            cVar.b = new androidx.work.impl.model.v(cVar);
        }
        androidx.work.impl.model.v vVar3 = cVar.b;
        String str18 = (String) vVar3.b;
        if (vVar3 == null) {
            cVar.b = new androidx.work.impl.model.v(cVar);
        }
        i.g = new K(str16, str13, str14, str17, str18, (String) cVar.b.c);
        C3941i0 c3941i0 = new C3941i0();
        c3941i0.a = 3;
        c3941i0.e = (byte) (c3941i0.e | 1);
        if (str4 == null) {
            throw new NullPointerException("Null version");
        }
        c3941i0.b = str4;
        if (str5 == null) {
            throw new NullPointerException("Null buildVersion");
        }
        c3941i0.c = str5;
        c3941i0.d = f.g();
        c3941i0.e = (byte) (c3941i0.e | 2);
        i.i = c3941i0.a();
        StatFs statFs2 = new StatFs(Environment.getDataDirectory().getPath());
        int iIntValue = 7;
        if (!TextUtils.isEmpty(str6) && (num = (Integer) r.f.get(str6.toLowerCase(locale))) != null) {
            iIntValue = num.intValue();
        }
        int iAvailableProcessors2 = Runtime.getRuntime().availableProcessors();
        long jA2 = f.a(rVar.a);
        long blockCount2 = statFs2.getBlockCount() * statFs2.getBlockSize();
        boolean zF2 = f.f();
        int iC2 = f.c();
        M m = new M();
        m.a = iIntValue;
        byte b2 = (byte) (m.j | 1);
        m.j = b2;
        if (str2 == null) {
            throw new NullPointerException("Null model");
        }
        m.b = str2;
        m.c = iAvailableProcessors2;
        m.d = jA2;
        m.e = blockCount2;
        m.f = zF2;
        m.g = iC2;
        m.j = (byte) (((byte) (((byte) (((byte) (((byte) (b2 | 2)) | 4)) | 8)) | 16)) | 32);
        if (str3 == null) {
            throw new NullPointerException("Null manufacturer");
        }
        m.h = str3;
        if (str9 == null) {
            throw new NullPointerException("Null modelClass");
        }
        m.i = str9;
        i.j = m.a();
        i.l = 3;
        i.m = (byte) (i.m | 4);
        a.j = i.a();
        B bA = a.a();
        com.google.firebase.crashlytics.internal.persistence.c cVar2 = ((com.google.firebase.crashlytics.internal.persistence.a) dVar2.b).b;
        J j3 = bA.k;
        if (j3 == null) {
            Log.isLoggable("FirebaseCrashlytics", 3);
            return;
        }
        String str19 = j3.b;
        try {
            com.google.firebase.crashlytics.internal.persistence.a.g.getClass();
            com.google.firebase.crashlytics.internal.persistence.a.f(cVar2.b(str19, "report"), com.google.firebase.crashlytics.internal.model.serialization.a.a.n(bA));
            File fileB = cVar2.b(str19, "start-time");
            long j4 = j3.d;
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(new FileOutputStream(fileB), com.google.firebase.crashlytics.internal.persistence.a.e);
            try {
                outputStreamWriter.write("");
                fileB.setLastModified(j4 * j);
                outputStreamWriter.close();
            } finally {
            }
        } catch (IOException unused) {
            Log.isLoggable("FirebaseCrashlytics", 3);
        }
    }

    public final boolean d(com.google.android.datatransport.cct.internal.s sVar) throws Throwable {
        com.google.firebase.crashlytics.internal.concurrency.d.a();
        s sVar2 = this.n;
        if (sVar2 != null && sVar2.e.get()) {
            Log.w("FirebaseCrashlytics", "Skipping session finalization because a crash has already occurred.", null);
            return false;
        }
        Log.isLoggable("FirebaseCrashlytics", 2);
        try {
            b(true, sVar, true);
            Log.isLoggable("FirebaseCrashlytics", 2);
            return true;
        } catch (Exception e) {
            Log.e("FirebaseCrashlytics", "Unable to finalize previously open sessions.", e);
            return false;
        }
    }

    public final String e() {
        NavigableSet navigableSetC = ((com.google.firebase.crashlytics.internal.persistence.a) this.m.b).c();
        if (navigableSetC.isEmpty()) {
            return null;
        }
        return (String) navigableSetC.first();
    }

    public final String f() throws Resources.NotFoundException, IOException {
        InputStream resourceAsStream;
        Context context = this.a;
        int iD = f.d(context, "com.google.firebase.crashlytics.version_control_info", "string");
        String string = iD == 0 ? null : context.getResources().getString(iD);
        if (string != null) {
            Log.isLoggable("FirebaseCrashlytics", 3);
            return Base64.encodeToString(string.getBytes(s), 0);
        }
        ClassLoader classLoader = m.class.getClassLoader();
        if (classLoader == null) {
            Log.w("FirebaseCrashlytics", "Couldn't get Class Loader", null);
            resourceAsStream = null;
        } else {
            resourceAsStream = classLoader.getResourceAsStream("META-INF/version-control-info.textproto");
        }
        if (resourceAsStream == null) {
            if (resourceAsStream != null) {
                resourceAsStream.close();
            }
            Log.i("FirebaseCrashlytics", "No version control information found", null);
            return null;
        }
        try {
            Log.isLoggable("FirebaseCrashlytics", 3);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            byte[] bArr = new byte[1024];
            while (true) {
                int i = resourceAsStream.read(bArr);
                if (i == -1) {
                    String strEncodeToString = Base64.encodeToString(byteArrayOutputStream.toByteArray(), 0);
                    resourceAsStream.close();
                    return strEncodeToString;
                }
                byteArrayOutputStream.write(bArr, 0, i);
            }
        } catch (Throwable th) {
            try {
                resourceAsStream.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    public final void g() throws Resources.NotFoundException {
        try {
            String strF = f();
            if (strF != null) {
                try {
                    ((androidx.browser.customtabs.k) this.d.e).i("com.crashlytics.version-control-info", strF);
                } catch (IllegalArgumentException e) {
                    Context context = this.a;
                    if (context != null) {
                        if ((context.getApplicationInfo().flags & 2) != 0) {
                            throw e;
                        }
                    }
                    Log.e("FirebaseCrashlytics", "Attempting to set custom attribute with null key, ignoring.", null);
                }
                Log.i("FirebaseCrashlytics", "Saved version control info", null);
            }
        } catch (IOException e2) {
            Log.w("FirebaseCrashlytics", "Unable to save version control info", e2);
        }
    }

    public final void h(com.google.android.gms.tasks.m mVar) {
        com.google.android.gms.tasks.m mVar2;
        com.google.android.gms.tasks.m mVarA;
        com.google.firebase.crashlytics.internal.persistence.c cVar = ((com.google.firebase.crashlytics.internal.persistence.a) this.m.b).b;
        boolean zIsEmpty = com.google.firebase.crashlytics.internal.persistence.c.e(cVar.e.listFiles()).isEmpty();
        com.google.android.gms.tasks.f fVar = this.o;
        if (zIsEmpty && com.google.firebase.crashlytics.internal.persistence.c.e(cVar.f.listFiles()).isEmpty() && com.google.firebase.crashlytics.internal.persistence.c.e(cVar.g.listFiles()).isEmpty()) {
            Log.isLoggable("FirebaseCrashlytics", 2);
            fVar.d(Boolean.FALSE);
            return;
        }
        Log.isLoggable("FirebaseCrashlytics", 2);
        com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = this.b;
        if (gVar.n()) {
            Log.isLoggable("FirebaseCrashlytics", 3);
            fVar.d(Boolean.FALSE);
            mVarA = S3.i(Boolean.TRUE);
        } else {
            Log.isLoggable("FirebaseCrashlytics", 3);
            Log.isLoggable("FirebaseCrashlytics", 2);
            fVar.d(Boolean.TRUE);
            synchronized (gVar.c) {
                mVar2 = ((com.google.android.gms.tasks.f) gVar.d).a;
            }
            Task taskM = mVar2.m(new com.google.mlkit.common.sdkinternal.model.a(18));
            Log.isLoggable("FirebaseCrashlytics", 3);
            mVarA = com.google.firebase.crashlytics.internal.concurrency.a.a(taskM, this.p.a);
        }
        mVarA.n(this.e.a, new com.quizlet.data.interactor.school.b(this, false, mVar, 12));
    }
}
