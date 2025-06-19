package com.google.firebase.crashlytics.internal.persistence;

import android.util.Log;
import androidx.camera.camera2.internal.a0;
import com.airbnb.lottie.parser.l;
import com.facebook.internal.H;
import com.google.android.datatransport.cct.internal.s;
import com.google.firebase.crashlytics.internal.common.h;
import com.google.firebase.crashlytics.internal.model.K0;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.NavigableSet;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public final class a {
    public static final Charset e = Charset.forName("UTF-8");
    public static final int f = 15;
    public static final com.google.firebase.crashlytics.internal.model.serialization.a g = new com.google.firebase.crashlytics.internal.model.serialization.a();
    public static final a0 h = new a0(16);
    public static final H i = new H(7);
    public final AtomicInteger a = new AtomicInteger(0);
    public final c b;
    public final s c;
    public final h d;

    public a(c cVar, s sVar, h hVar) {
        this.b = cVar;
        this.c = sVar;
        this.d = hVar;
    }

    public static void a(List list) {
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            ((File) it2.next()).delete();
        }
    }

    public static String e(File file) {
        byte[] bArr = new byte[8192];
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        FileInputStream fileInputStream = new FileInputStream(file);
        while (true) {
            try {
                int i2 = fileInputStream.read(bArr);
                if (i2 <= 0) {
                    String str = new String(byteArrayOutputStream.toByteArray(), e);
                    fileInputStream.close();
                    return str;
                }
                byteArrayOutputStream.write(bArr, 0, i2);
            } catch (Throwable th) {
                try {
                    fileInputStream.close();
                } catch (Throwable th2) {
                    th.addSuppressed(th2);
                }
                throw th;
            }
        }
    }

    public static void f(File file, String str) {
        OutputStreamWriter outputStreamWriter = new OutputStreamWriter(new FileOutputStream(file), e);
        try {
            outputStreamWriter.write(str);
            outputStreamWriter.close();
        } catch (Throwable th) {
            try {
                outputStreamWriter.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }

    public final ArrayList b() {
        ArrayList arrayList = new ArrayList();
        c cVar = this.b;
        arrayList.addAll(c.e(cVar.f.listFiles()));
        arrayList.addAll(c.e(cVar.g.listFiles()));
        a0 a0Var = h;
        Collections.sort(arrayList, a0Var);
        List listE = c.e(cVar.e.listFiles());
        Collections.sort(listE, a0Var);
        arrayList.addAll(listE);
        return arrayList;
    }

    public final NavigableSet c() {
        return new TreeSet(c.e(this.b.d.list())).descendingSet();
    }

    public final void d(K0 k0, String str, boolean z) {
        c cVar = this.b;
        l lVar = this.c.l().a;
        g.getClass();
        try {
            f(cVar.b(str, android.support.v4.media.session.a.B("event", String.format(Locale.US, "%010d", Integer.valueOf(this.a.getAndIncrement())), z ? "_" : "")), com.google.firebase.crashlytics.internal.model.serialization.a.a.n(k0));
        } catch (IOException e2) {
            Log.w("FirebaseCrashlytics", "Could not persist event for session " + str, e2);
        }
        H h2 = new H(8);
        cVar.getClass();
        File file = new File(cVar.d, str);
        file.mkdirs();
        List<File> listE = c.e(file.listFiles(h2));
        Collections.sort(listE, new a0(17));
        int size = listE.size();
        for (File file2 : listE) {
            if (size <= lVar.b) {
                return;
            }
            c.d(file2);
            size--;
        }
    }
}
