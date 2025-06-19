package com.bumptech.glide.disklrucache;

import android.os.StrictMode;
import androidx.browser.customtabs.k;
import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/* loaded from: classes.dex */
public final class c implements Closeable, AutoCloseable {
    public final File a;
    public final File b;
    public final File c;
    public final File d;
    public final long f;
    public BufferedWriter i;
    public int k;
    public long h = 0;
    public final LinkedHashMap j = new LinkedHashMap(0, 0.75f, true);
    public long l = 0;
    public final ThreadPoolExecutor m = new ThreadPoolExecutor(0, 1, 60, TimeUnit.SECONDS, new LinkedBlockingQueue(), new a());
    public final androidx.camera.core.impl.utils.executor.c n = new androidx.camera.core.impl.utils.executor.c(this, 4);
    public final int e = 1;
    public final int g = 1;

    public c(File file, long j) {
        this.a = file;
        this.b = new File(file, "journal");
        this.c = new File(file, "journal.tmp");
        this.d = new File(file, "journal.bkp");
        this.f = j;
    }

    public static void D(File file, File file2, boolean z) throws IOException {
        if (z) {
            f(file2);
        }
        if (!file.renameTo(file2)) {
            throw new IOException();
        }
    }

    public static void a(c cVar, k kVar, boolean z) {
        synchronized (cVar) {
            b bVar = (b) kVar.b;
            if (bVar.f != kVar) {
                throw new IllegalStateException();
            }
            if (z && !bVar.e) {
                for (int i = 0; i < cVar.g; i++) {
                    if (!((boolean[]) kVar.c)[i]) {
                        kVar.b();
                        throw new IllegalStateException("Newly created entry didn't create value for index " + i);
                    }
                    if (!bVar.d[i].exists()) {
                        kVar.b();
                        return;
                    }
                }
            }
            for (int i2 = 0; i2 < cVar.g; i2++) {
                File file = bVar.d[i2];
                if (!z) {
                    f(file);
                } else if (file.exists()) {
                    File file2 = bVar.c[i2];
                    file.renameTo(file2);
                    long j = bVar.b[i2];
                    long length = file2.length();
                    bVar.b[i2] = length;
                    cVar.h = (cVar.h - j) + length;
                }
            }
            cVar.k++;
            bVar.f = null;
            if (bVar.e || z) {
                bVar.e = true;
                cVar.i.append((CharSequence) "CLEAN");
                cVar.i.append(' ');
                cVar.i.append((CharSequence) bVar.a);
                cVar.i.append((CharSequence) bVar.a());
                cVar.i.append('\n');
                if (z) {
                    cVar.l++;
                }
            } else {
                cVar.j.remove(bVar.a);
                cVar.i.append((CharSequence) "REMOVE");
                cVar.i.append(' ');
                cVar.i.append((CharSequence) bVar.a);
                cVar.i.append('\n');
            }
            j(cVar.i);
            if (cVar.h > cVar.f || cVar.p()) {
                cVar.m.submit(cVar.n);
            }
        }
    }

    public static void d(BufferedWriter bufferedWriter) {
        StrictMode.ThreadPolicy threadPolicy = StrictMode.getThreadPolicy();
        StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder(threadPolicy).permitUnbufferedIo().build());
        try {
            bufferedWriter.close();
        } finally {
            StrictMode.setThreadPolicy(threadPolicy);
        }
    }

    public static void f(File file) throws IOException {
        if (file.exists() && !file.delete()) {
            throw new IOException();
        }
    }

    public static void j(BufferedWriter bufferedWriter) {
        StrictMode.ThreadPolicy threadPolicy = StrictMode.getThreadPolicy();
        StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder(threadPolicy).permitUnbufferedIo().build());
        try {
            bufferedWriter.flush();
        } finally {
            StrictMode.setThreadPolicy(threadPolicy);
        }
    }

    public static c q(File file, long j) throws IOException {
        if (j <= 0) {
            throw new IllegalArgumentException("maxSize <= 0");
        }
        File file2 = new File(file, "journal.bkp");
        if (file2.exists()) {
            File file3 = new File(file, "journal");
            if (file3.exists()) {
                file2.delete();
            } else {
                D(file2, file3, false);
            }
        }
        c cVar = new c(file, j);
        if (cVar.b.exists()) {
            try {
                cVar.y();
                cVar.r();
                return cVar;
            } catch (IOException e) {
                System.out.println("DiskLruCache " + file + " is corrupt: " + e.getMessage() + ", removing");
                cVar.close();
                f.a(cVar.a);
            }
        }
        file.mkdirs();
        c cVar2 = new c(file, j);
        cVar2.C();
        return cVar2;
    }

    public final void B(String str) throws IOException {
        String strSubstring;
        int iIndexOf = str.indexOf(32);
        if (iIndexOf == -1) {
            throw new IOException("unexpected journal line: ".concat(str));
        }
        int i = iIndexOf + 1;
        int iIndexOf2 = str.indexOf(32, i);
        LinkedHashMap linkedHashMap = this.j;
        if (iIndexOf2 == -1) {
            strSubstring = str.substring(i);
            if (iIndexOf == 6 && str.startsWith("REMOVE")) {
                linkedHashMap.remove(strSubstring);
                return;
            }
        } else {
            strSubstring = str.substring(i, iIndexOf2);
        }
        b bVar = (b) linkedHashMap.get(strSubstring);
        if (bVar == null) {
            bVar = new b(this, strSubstring);
            linkedHashMap.put(strSubstring, bVar);
        }
        if (iIndexOf2 == -1 || iIndexOf != 5 || !str.startsWith("CLEAN")) {
            if (iIndexOf2 == -1 && iIndexOf == 5 && str.startsWith("DIRTY")) {
                bVar.f = new k(this, bVar);
                return;
            } else {
                if (iIndexOf2 != -1 || iIndexOf != 4 || !str.startsWith("READ")) {
                    throw new IOException("unexpected journal line: ".concat(str));
                }
                return;
            }
        }
        String[] strArrSplit = str.substring(iIndexOf2 + 1).split(" ");
        bVar.e = true;
        bVar.f = null;
        if (strArrSplit.length != bVar.g.g) {
            throw new IOException("unexpected journal line: " + Arrays.toString(strArrSplit));
        }
        for (int i2 = 0; i2 < strArrSplit.length; i2++) {
            try {
                bVar.b[i2] = Long.parseLong(strArrSplit[i2]);
            } catch (NumberFormatException unused) {
                throw new IOException("unexpected journal line: " + Arrays.toString(strArrSplit));
            }
        }
    }

    public final synchronized void C() {
        try {
            BufferedWriter bufferedWriter = this.i;
            if (bufferedWriter != null) {
                d(bufferedWriter);
            }
            BufferedWriter bufferedWriter2 = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(this.c), f.a));
            try {
                bufferedWriter2.write("libcore.io.DiskLruCache");
                bufferedWriter2.write("\n");
                bufferedWriter2.write("1");
                bufferedWriter2.write("\n");
                bufferedWriter2.write(Integer.toString(this.e));
                bufferedWriter2.write("\n");
                bufferedWriter2.write(Integer.toString(this.g));
                bufferedWriter2.write("\n");
                bufferedWriter2.write("\n");
                for (b bVar : this.j.values()) {
                    if (bVar.f != null) {
                        bufferedWriter2.write("DIRTY " + bVar.a + '\n');
                    } else {
                        bufferedWriter2.write("CLEAN " + bVar.a + bVar.a() + '\n');
                    }
                }
                d(bufferedWriter2);
                if (this.b.exists()) {
                    D(this.b, this.d, true);
                }
                D(this.c, this.b, false);
                this.d.delete();
                this.i = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(this.b, true), f.a));
            } catch (Throwable th) {
                d(bufferedWriter2);
                throw th;
            }
        } catch (Throwable th2) {
            throw th2;
        }
    }

    public final void P() {
        while (this.h > this.f) {
            String str = (String) ((Map.Entry) this.j.entrySet().iterator().next()).getKey();
            synchronized (this) {
                try {
                    if (this.i == null) {
                        throw new IllegalStateException("cache is closed");
                    }
                    b bVar = (b) this.j.get(str);
                    if (bVar != null && bVar.f == null) {
                        for (int i = 0; i < this.g; i++) {
                            File file = bVar.c[i];
                            if (file.exists() && !file.delete()) {
                                throw new IOException("failed to delete " + file);
                            }
                            long j = this.h;
                            long[] jArr = bVar.b;
                            this.h = j - jArr[i];
                            jArr[i] = 0;
                        }
                        this.k++;
                        this.i.append((CharSequence) "REMOVE");
                        this.i.append(' ');
                        this.i.append((CharSequence) str);
                        this.i.append('\n');
                        this.j.remove(str);
                        if (p()) {
                            this.m.submit(this.n);
                        }
                    }
                } finally {
                }
            }
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final synchronized void close() {
        try {
            if (this.i == null) {
                return;
            }
            Iterator it2 = new ArrayList(this.j.values()).iterator();
            while (it2.hasNext()) {
                k kVar = ((b) it2.next()).f;
                if (kVar != null) {
                    kVar.b();
                }
            }
            P();
            d(this.i);
            this.i = null;
        } catch (Throwable th) {
            throw th;
        }
    }

    public final k i(String str) {
        synchronized (this) {
            try {
                if (this.i == null) {
                    throw new IllegalStateException("cache is closed");
                }
                b bVar = (b) this.j.get(str);
                if (bVar == null) {
                    bVar = new b(this, str);
                    this.j.put(str, bVar);
                } else if (bVar.f != null) {
                    return null;
                }
                k kVar = new k(this, bVar);
                bVar.f = kVar;
                this.i.append((CharSequence) "DIRTY");
                this.i.append(' ');
                this.i.append((CharSequence) str);
                this.i.append('\n');
                j(this.i);
                return kVar;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final synchronized com.quizlet.data.repository.school.membership.a l(String str) {
        if (this.i == null) {
            throw new IllegalStateException("cache is closed");
        }
        b bVar = (b) this.j.get(str);
        if (bVar == null) {
            return null;
        }
        if (!bVar.e) {
            return null;
        }
        for (File file : bVar.c) {
            if (!file.exists()) {
                return null;
            }
        }
        this.k++;
        this.i.append((CharSequence) "READ");
        this.i.append(' ');
        this.i.append((CharSequence) str);
        this.i.append('\n');
        if (p()) {
            this.m.submit(this.n);
        }
        return new com.quizlet.data.repository.school.membership.a(bVar.c, 14);
    }

    public final boolean p() {
        int i = this.k;
        return i >= 2000 && i >= this.j.size();
    }

    public final void r() throws IOException {
        f(this.c);
        Iterator it2 = this.j.values().iterator();
        while (it2.hasNext()) {
            b bVar = (b) it2.next();
            k kVar = bVar.f;
            int i = this.g;
            int i2 = 0;
            if (kVar == null) {
                while (i2 < i) {
                    this.h += bVar.b[i2];
                    i2++;
                }
            } else {
                bVar.f = null;
                while (i2 < i) {
                    f(bVar.c[i2]);
                    f(bVar.d[i2]);
                    i2++;
                }
                it2.remove();
            }
        }
    }

    public final void y() {
        File file = this.b;
        e eVar = new e(new FileInputStream(file), f.a);
        try {
            String strA = eVar.a();
            String strA2 = eVar.a();
            String strA3 = eVar.a();
            String strA4 = eVar.a();
            String strA5 = eVar.a();
            if (!"libcore.io.DiskLruCache".equals(strA) || !"1".equals(strA2) || !Integer.toString(this.e).equals(strA3) || !Integer.toString(this.g).equals(strA4) || !"".equals(strA5)) {
                throw new IOException("unexpected journal header: [" + strA + ", " + strA2 + ", " + strA4 + ", " + strA5 + "]");
            }
            int i = 0;
            while (true) {
                try {
                    B(eVar.a());
                    i++;
                } catch (EOFException unused) {
                    this.k = i - this.j.size();
                    if (eVar.e == -1) {
                        C();
                    } else {
                        this.i = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(file, true), f.a));
                    }
                    try {
                        eVar.close();
                        return;
                    } catch (RuntimeException e) {
                        throw e;
                    } catch (Exception unused2) {
                        return;
                    }
                }
            }
        } catch (Throwable th) {
            try {
                eVar.close();
            } catch (RuntimeException e2) {
                throw e2;
            } catch (Exception unused3) {
            }
            throw th;
        }
    }
}
