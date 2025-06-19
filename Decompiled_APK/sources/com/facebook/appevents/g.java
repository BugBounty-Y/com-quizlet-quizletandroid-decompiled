package com.facebook.appevents;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.util.Log;
import android.webkit.MimeTypeMap;
import androidx.appcompat.widget.N0;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.foundation.layout.A;
import androidx.compose.foundation.layout.AbstractC0382e;
import androidx.compose.foundation.layout.AbstractC0398m;
import androidx.compose.foundation.layout.B;
import androidx.compose.material3.Q4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0803j0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.node.C0912h;
import androidx.compose.ui.node.C0913i;
import androidx.compose.ui.node.C0914j;
import androidx.compose.ui.node.InterfaceC0915k;
import androidx.compose.ui.text.L;
import androidx.work.P;
import com.facebook.internal.J;
import com.google.android.gms.internal.measurement.AbstractC3058t1;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3106b5;
import com.quizlet.data.model.C4114c;
import com.quizlet.quizletandroid.R;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.logging.Logger;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import okio.AbstractC5085b;
import okio.C5086c;
import okio.I;
import okio.InterfaceC5093j;
import okio.z;

/* loaded from: classes.dex */
public abstract class g {
    public static final void a(C4114c badgeData, androidx.compose.ui.q qVar, Function0 function0, InterfaceC0806l interfaceC0806l, int i) {
        Intrinsics.checkNotNullParameter(badgeData, "badgeData");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1066189935);
        int i2 = i | (c0814p.h(badgeData) ? 4 : 2);
        if ((i & 48) == 0) {
            i2 |= c0814p.f(qVar) ? 32 : 16;
        }
        int i3 = i2 | (c0814p.h(function0) ? 256 : 128);
        if ((i3 & 147) == 146 && c0814p.x()) {
            c0814p.Q();
        } else {
            B bA = A.a(AbstractC0398m.c, androidx.compose.ui.b.n, c0814p, 48);
            int i4 = c0814p.P;
            InterfaceC0803j0 interfaceC0803j0L = c0814p.l();
            androidx.compose.ui.q qVarC = androidx.compose.ui.a.c(c0814p, qVar);
            InterfaceC0915k.D0.getClass();
            C0913i c0913i = C0914j.b;
            c0814p.b0();
            if (c0814p.O) {
                c0814p.k(c0913i);
            } else {
                c0814p.l0();
            }
            C0776c.E(c0814p, bA, C0914j.f);
            C0776c.E(c0814p, interfaceC0803j0L, C0914j.e);
            C0912h c0912h = C0914j.g;
            if (c0814p.O || !Intrinsics.b(c0814p.I(), Integer.valueOf(i4))) {
                android.support.v4.media.session.a.z(i4, c0814p, i4, c0912h);
            }
            C0776c.E(c0814p, qVarC, C0914j.d);
            AbstractC3058t1.a(badgeData, null, DefinitionKt.NO_Float_VALUE, function0, c0814p, (i3 & 14) | ((i3 << 3) & 7168), 6);
            androidx.compose.runtime.B b = com.quizlet.themes.w.b;
            L l = ((com.quizlet.themes.f) c0814p.j(b)).j;
            androidx.compose.ui.n nVar = androidx.compose.ui.n.b;
            com.quizlet.themes.m.g.q();
            Q4.b(badgeData.d, AbstractC0382e.y(nVar, DefinitionKt.NO_Float_VALUE, com.quizlet.ui.resources.designsystem.generated.j.i, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 13), 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l, c0814p, 0, 0, 65020);
            String strD = P.d(badgeData);
            if (strD == null) {
                strD = "";
            }
            String strC = AbstractC3106b5.c(R.string.achievements_badge_earned, new Object[]{strD}, c0814p);
            L l2 = ((com.quizlet.themes.f) c0814p.j(b)).p;
            String strD2 = P.d(badgeData);
            Q4.b(strC, androidx.compose.ui.draw.g.a(nVar, (strD2 == null || strD2.length() == 0) ? DefinitionKt.NO_Float_VALUE : 1.0f), 0L, 0L, null, 0L, new androidx.compose.ui.text.style.i(3), 0L, 0, false, 0, 0, null, l2, c0814p, 0, 0, 65020);
            c0814p.p(true);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new androidx.navigation.compose.u(i, 5, badgeData, qVar, function0);
        }
    }

    public static final void b(Context context, String cacheName) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(cacheName, "cacheName");
        File file = new File(context.getExternalCacheDir(), cacheName);
        File file2 = new File(context.getCacheDir(), cacheName);
        if (d(file)) {
            d(file2);
        }
    }

    public static final Uri c(Context context, com.quizlet.qutils.image.capture.a imageCache, Uri sourceUri, boolean z) throws IOException {
        String extensionFromMimeType;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(imageCache, "imageCache");
        Intrinsics.checkNotNullParameter(sourceUri, "sourceUri");
        if (z) {
            extensionFromMimeType = null;
        } else {
            String type = context.getContentResolver().getType(sourceUri);
            extensionFromMimeType = type == null ? "png" : MimeTypeMap.getSingleton().getExtensionFromMimeType(type);
        }
        Uri destUri = Uri.fromFile(imageCache.b(context, extensionFromMimeType));
        Intrinsics.d(destUri);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(sourceUri, "sourceUri");
        Intrinsics.checkNotNullParameter(destUri, "destUri");
        InputStream inputStreamOpenInputStream = context.getContentResolver().openInputStream(sourceUri);
        OutputStream outputStreamOpenOutputStream = context.getContentResolver().openOutputStream(destUri);
        if (inputStreamOpenInputStream != null && outputStreamOpenOutputStream != null) {
            int i = com.google.common.io.a.a;
            byte[] bArr = new byte[8192];
            while (true) {
                int i2 = inputStreamOpenInputStream.read(bArr);
                if (i2 == -1) {
                    break;
                }
                outputStreamOpenOutputStream.write(bArr, 0, i2);
            }
        }
        return destUri;
    }

    public static final boolean d(File file) {
        String[] list;
        if (!file.exists() || (list = file.list()) == null) {
            return true;
        }
        if (file.isDirectory()) {
            ArrayList arrayList = new ArrayList(list.length);
            for (String str : list) {
                arrayList.add(Boolean.valueOf(d(new File(file, str))));
            }
            if (!arrayList.isEmpty()) {
                Iterator it2 = arrayList.iterator();
                while (it2.hasNext()) {
                    if (!((Boolean) it2.next()).booleanValue()) {
                        return false;
                    }
                }
            }
        }
        return file.delete();
    }

    public static final File e(Context context, String cacheName) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(cacheName, "cacheName");
        File externalCacheDir = context.getExternalCacheDir();
        if (externalCacheDir == null) {
            externalCacheDir = context.getCacheDir();
        }
        if (externalCacheDir == null) {
            timber.log.c.a.d("Unable to get cache directory", new Object[0]);
            externalCacheDir = context.getCacheDir();
        }
        File file = new File(externalCacheDir, cacheName);
        if (!file.exists()) {
            file.mkdir();
        }
        return file;
    }

    public static Drawable f(Context context, int i) {
        return N0.b().c(context, i);
    }

    public static final ArrayList g(File file) {
        ArrayList arrayList = new ArrayList();
        if (file.isDirectory()) {
            File[] fileArrListFiles = file.listFiles();
            if (fileArrListFiles == null) {
                fileArrListFiles = new File[0];
            }
            for (File file2 : fileArrListFiles) {
                if (file2.isDirectory()) {
                    arrayList.addAll(g(file2));
                } else {
                    arrayList.add(file2);
                }
            }
        }
        return arrayList;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0099 A[Catch: all -> 0x0035, TRY_LEAVE, TryCatch #4 {, blocks: (B:4:0x0003, B:8:0x0028, B:9:0x002b, B:46:0x0099, B:14:0x0039, B:34:0x006e, B:35:0x0071, B:39:0x0083, B:38:0x007c, B:28:0x0058, B:29:0x005b, B:33:0x006a, B:40:0x0084, B:41:0x0087), top: B:57:0x0003, inners: #3, #5 }] */
    /* JADX WARN: Type inference failed for: r1v12, types: [java.lang.Exception, java.lang.Throwable] */
    /* JADX WARN: Type inference failed for: r4v14, types: [java.lang.String] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final synchronized com.facebook.appevents.t h() {
        /*
            java.lang.Class<com.facebook.appevents.g> r0 = com.facebook.appevents.g.class
            monitor-enter(r0)
            android.content.Context r1 = com.facebook.o.a()     // Catch: java.lang.Throwable -> L35
            r2 = 0
            java.lang.String r3 = "AppEventsLogger.persistedevents"
            java.io.FileInputStream r3 = r1.openFileInput(r3)     // Catch: java.io.FileNotFoundException -> L4b java.lang.Throwable -> L4d java.lang.Exception -> L4f
            java.lang.String r4 = "context.openFileInput(PERSISTED_EVENTS_FILENAME)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r4)     // Catch: java.io.FileNotFoundException -> L4b java.lang.Throwable -> L4d java.lang.Exception -> L4f
            com.facebook.appevents.f r4 = new com.facebook.appevents.f     // Catch: java.io.FileNotFoundException -> L4b java.lang.Throwable -> L4d java.lang.Exception -> L4f
            java.io.BufferedInputStream r5 = new java.io.BufferedInputStream     // Catch: java.io.FileNotFoundException -> L4b java.lang.Throwable -> L4d java.lang.Exception -> L4f
            r5.<init>(r3)     // Catch: java.io.FileNotFoundException -> L4b java.lang.Throwable -> L4d java.lang.Exception -> L4f
            r4.<init>(r5)     // Catch: java.io.FileNotFoundException -> L4b java.lang.Throwable -> L4d java.lang.Exception -> L4f
            java.lang.Object r3 = r4.readObject()     // Catch: java.lang.Throwable -> L42 java.lang.Exception -> L44 java.io.FileNotFoundException -> L84
            java.lang.String r5 = "null cannot be cast to non-null type com.facebook.appevents.PersistedEvents"
            kotlin.jvm.internal.Intrinsics.e(r3, r5)     // Catch: java.lang.Throwable -> L42 java.lang.Exception -> L44 java.io.FileNotFoundException -> L84
            com.facebook.appevents.t r3 = (com.facebook.appevents.t) r3     // Catch: java.lang.Throwable -> L42 java.lang.Exception -> L44 java.io.FileNotFoundException -> L84
            com.facebook.internal.J.d(r4)     // Catch: java.lang.Throwable -> L35
            java.lang.String r2 = "AppEventsLogger.persistedevents"
            java.io.File r1 = r1.getFileStreamPath(r2)     // Catch: java.lang.Throwable -> L35 java.lang.Exception -> L38
            r1.delete()     // Catch: java.lang.Throwable -> L35 java.lang.Exception -> L38
            goto L40
        L35:
            r1 = move-exception
            goto La0
        L38:
            r1 = move-exception
            java.lang.String r2 = "com.facebook.appevents.g"
            java.lang.String r4 = "Got unexpected exception when removing events file: "
            android.util.Log.w(r2, r4, r1)     // Catch: java.lang.Throwable -> L35
        L40:
            r2 = r3
            goto L97
        L42:
            r2 = move-exception
            goto L6e
        L44:
            r3 = move-exception
            goto L51
        L46:
            r4 = r2
            r2 = r3
            goto L6e
        L49:
            r4 = r2
            goto L51
        L4b:
            r4 = r2
            goto L84
        L4d:
            r3 = move-exception
            goto L46
        L4f:
            r3 = move-exception
            goto L49
        L51:
            java.lang.String r5 = "com.facebook.appevents.g"
            java.lang.String r6 = "Got unexpected exception while reading events: "
            android.util.Log.w(r5, r6, r3)     // Catch: java.lang.Throwable -> L42
            com.facebook.internal.J.d(r4)     // Catch: java.lang.Throwable -> L35
            java.lang.String r3 = "AppEventsLogger.persistedevents"
            java.io.File r1 = r1.getFileStreamPath(r3)     // Catch: java.lang.Throwable -> L35 java.lang.Exception -> L65
            r1.delete()     // Catch: java.lang.Throwable -> L35 java.lang.Exception -> L65
            goto L97
        L65:
            r1 = move-exception
            java.lang.String r3 = "com.facebook.appevents.g"
            java.lang.String r4 = "Got unexpected exception when removing events file: "
        L6a:
            android.util.Log.w(r3, r4, r1)     // Catch: java.lang.Throwable -> L35
            goto L97
        L6e:
            com.facebook.internal.J.d(r4)     // Catch: java.lang.Throwable -> L35
            java.lang.String r3 = "AppEventsLogger.persistedevents"
            java.io.File r1 = r1.getFileStreamPath(r3)     // Catch: java.lang.Throwable -> L35 java.lang.Exception -> L7b
            r1.delete()     // Catch: java.lang.Throwable -> L35 java.lang.Exception -> L7b
            goto L83
        L7b:
            r1 = move-exception
            java.lang.String r3 = "com.facebook.appevents.g"
            java.lang.String r4 = "Got unexpected exception when removing events file: "
            android.util.Log.w(r3, r4, r1)     // Catch: java.lang.Throwable -> L35
        L83:
            throw r2     // Catch: java.lang.Throwable -> L35
        L84:
            com.facebook.internal.J.d(r4)     // Catch: java.lang.Throwable -> L35
            java.lang.String r3 = "AppEventsLogger.persistedevents"
            java.io.File r1 = r1.getFileStreamPath(r3)     // Catch: java.lang.Throwable -> L35 java.lang.Exception -> L91
            r1.delete()     // Catch: java.lang.Throwable -> L35 java.lang.Exception -> L91
            goto L97
        L91:
            r1 = move-exception
            java.lang.String r3 = "com.facebook.appevents.g"
            java.lang.String r4 = "Got unexpected exception when removing events file: "
            goto L6a
        L97:
            if (r2 != 0) goto L9e
            com.facebook.appevents.t r2 = new com.facebook.appevents.t     // Catch: java.lang.Throwable -> L35
            r2.<init>()     // Catch: java.lang.Throwable -> L35
        L9e:
            monitor-exit(r0)
            return r2
        La0:
            monitor-exit(r0)     // Catch: java.lang.Throwable -> L35
            throw r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.g.h():com.facebook.appevents.t");
    }

    public static final void i(t tVar) {
        ObjectOutputStream objectOutputStream;
        Context contextA = com.facebook.o.a();
        ObjectOutputStream objectOutputStream2 = null;
        try {
            objectOutputStream = new ObjectOutputStream(new BufferedOutputStream(contextA.openFileOutput("AppEventsLogger.persistedevents", 0)));
        } catch (Throwable th) {
            th = th;
        }
        try {
            objectOutputStream.writeObject(tVar);
            J.d(objectOutputStream);
        } catch (Throwable th2) {
            th = th2;
            objectOutputStream2 = objectOutputStream;
            try {
                Log.w("com.facebook.appevents.g", "Got unexpected exception while persisting events: ", th);
                try {
                    contextA.getFileStreamPath("AppEventsLogger.persistedevents").delete();
                } catch (Exception unused) {
                }
            } finally {
                J.d(objectOutputStream2);
            }
        }
    }

    public static final void j(InterfaceC5093j source, File file) throws IOException {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(file, "file");
        try {
            if (!file.exists()) {
                File parentFile = file.getParentFile();
                if (parentFile != null) {
                    parentFile.mkdirs();
                }
                file.createNewFile();
            }
            Logger logger = okio.v.a;
            Intrinsics.checkNotNullParameter(file, "<this>");
            FileOutputStream fileOutputStream = new FileOutputStream(file, false);
            Intrinsics.checkNotNullParameter(fileOutputStream, "<this>");
            z zVarB = AbstractC5085b.b(new C5086c(fileOutputStream, new I()));
            try {
                zVarB.M(source);
                zVarB.flush();
            } finally {
                zVarB.close();
                source.close();
            }
        } catch (IOException e) {
            timber.log.a aVar = timber.log.c.a;
            String name = file.getName();
            String path = file.getPath();
            aVar.o(AbstractC0147y.g(AbstractC0147y.h("Exception when trying to writeToFile. File name: ", name, " - File path: ", path, " - File absolute path: "), file.getAbsolutePath(), ". Exception: ", e.getMessage()), new Object[0]);
            throw e;
        }
    }
}
