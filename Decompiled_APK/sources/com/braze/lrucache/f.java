package com.braze.lrucache;

import com.braze.AbstractC1475a;
import com.braze.support.BrazeLogger;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/* loaded from: classes.dex */
public final class f {
    public static final Pattern o = Pattern.compile("[a-z0-9_-]{1,120}");
    public static final String p = BrazeLogger.getBrazeLogTag((Class<?>) f.class);
    public static final b q = new b();
    public final File a;
    public final File b;
    public final File c;
    public final File d;
    public BufferedWriter i;
    public int k;
    public long h = 0;
    public final LinkedHashMap j = new LinkedHashMap(0, 0.75f, true);
    public long l = 0;
    public final ThreadPoolExecutor m = new ThreadPoolExecutor(0, 1, 60, TimeUnit.SECONDS, new LinkedBlockingQueue());
    public final a n = new a(this);
    public final int e = 1;
    public final int g = 1;
    public final long f = 52428800;

    public f(File file) {
        this.a = file;
        this.b = new File(file, "journal");
        this.c = new File(file, "journal.tmp");
        this.d = new File(file, "journal.bkp");
    }

    public static void a(f fVar, d dVar, boolean z) {
        synchronized (fVar) {
            g gVar = dVar.a;
            if (gVar.d != dVar) {
                throw new IllegalStateException();
            }
            if (z && !gVar.c) {
                for (int i = 0; i < fVar.g; i++) {
                    if (!dVar.b[i]) {
                        a(dVar.d, dVar, false);
                        throw new IllegalStateException("Newly created entry didn't create value for index " + i);
                    }
                    if (!gVar.a(i).exists()) {
                        a(dVar.d, dVar, false);
                        return;
                    }
                }
            }
            for (int i2 = 0; i2 < fVar.g; i2++) {
                File fileA = gVar.a(i2);
                if (z) {
                    if (fileA.exists()) {
                        File file = new File(gVar.f, gVar.a + "." + i2);
                        fileA.renameTo(file);
                        long j = gVar.b[i2];
                        long length = file.length();
                        gVar.b[i2] = length;
                        fVar.h = (fVar.h - j) + length;
                    }
                } else if (fileA.exists() && !fileA.delete()) {
                    throw new IOException();
                }
            }
            fVar.k++;
            gVar.d = null;
            if (gVar.c || z) {
                gVar.c = true;
                BufferedWriter bufferedWriter = fVar.i;
                StringBuilder sb = new StringBuilder("CLEAN ");
                sb.append(gVar.a);
                StringBuilder sb2 = new StringBuilder();
                for (long j2 : gVar.b) {
                    sb2.append(' ');
                    sb2.append(j2);
                }
                sb.append(sb2.toString());
                sb.append('\n');
                bufferedWriter.write(sb.toString());
                if (z) {
                    fVar.l++;
                }
            } else {
                fVar.j.remove(gVar.a);
                fVar.i.write("REMOVE " + gVar.a + '\n');
            }
            fVar.i.flush();
            if (fVar.h > fVar.f || fVar.a()) {
                fVar.m.submit(fVar.n);
            }
        }
    }

    public final void b() throws IOException {
        File file = this.c;
        if (file.exists() && !file.delete()) {
            throw new IOException();
        }
        Iterator it2 = this.j.values().iterator();
        while (it2.hasNext()) {
            g gVar = (g) it2.next();
            int i = 0;
            if (gVar.d == null) {
                while (i < this.g) {
                    this.h += gVar.b[i];
                    i++;
                }
            } else {
                gVar.d = null;
                while (i < this.g) {
                    File file2 = new File(gVar.f, gVar.a + "." + i);
                    if (file2.exists() && !file2.delete()) {
                        throw new IOException();
                    }
                    File fileA = gVar.a(i);
                    if (fileA.exists() && !fileA.delete()) {
                        throw new IOException();
                    }
                    i++;
                }
                it2.remove();
            }
        }
    }

    public final void c() {
        i iVar = new i(new FileInputStream(this.b), j.a);
        try {
            String strA = iVar.a();
            String strA2 = iVar.a();
            String strA3 = iVar.a();
            String strA4 = iVar.a();
            String strA5 = iVar.a();
            if (!"libcore.io.DiskLruCache".equals(strA) || !"1".equals(strA2) || !Integer.toString(this.e).equals(strA3) || !Integer.toString(this.g).equals(strA4) || !"".equals(strA5)) {
                throw new IOException("unexpected journal header: [" + strA + ", " + strA2 + ", " + strA4 + ", " + strA5 + "]");
            }
            int i = 0;
            while (true) {
                try {
                    c(iVar.a());
                    i++;
                } catch (EOFException unused) {
                    this.k = i - this.j.size();
                    if (iVar.e == -1) {
                        d();
                    } else {
                        this.i = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(this.b, true), j.a));
                    }
                    try {
                        iVar.close();
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
                iVar.close();
            } catch (RuntimeException e2) {
                throw e2;
            } catch (Exception unused3) {
            }
            throw th;
        }
    }

    public final synchronized void d() {
        try {
            BufferedWriter bufferedWriter = this.i;
            if (bufferedWriter != null) {
                bufferedWriter.close();
            }
            BufferedWriter bufferedWriter2 = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(this.c), j.a));
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
                for (g gVar : this.j.values()) {
                    if (gVar.d != null) {
                        bufferedWriter2.write("DIRTY " + gVar.a + '\n');
                    } else {
                        StringBuilder sb = new StringBuilder();
                        sb.append("CLEAN ");
                        sb.append(gVar.a);
                        StringBuilder sb2 = new StringBuilder();
                        for (long j : gVar.b) {
                            sb2.append(' ');
                            sb2.append(j);
                        }
                        sb.append(sb2.toString());
                        sb.append('\n');
                        bufferedWriter2.write(sb.toString());
                    }
                }
                bufferedWriter2.close();
                if (this.b.exists()) {
                    File file = this.b;
                    File file2 = this.d;
                    if (file2.exists() && !file2.delete()) {
                        throw new IOException();
                    }
                    if (!file.renameTo(file2)) {
                        throw new IOException();
                    }
                }
                if (!this.c.renameTo(this.b)) {
                    throw new IOException();
                }
                this.d.delete();
                this.i = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(this.b, true), j.a));
            } finally {
                try {
                    bufferedWriter2.close();
                } catch (Throwable th) {
                    th.addSuppressed(th);
                }
            }
        } catch (Throwable th2) {
            throw th2;
        }
    }

    public final synchronized e b(String str) {
        InputStream inputStream;
        if (this.i != null) {
            if (o.matcher(str).matches()) {
                g gVar = (g) this.j.get(str);
                if (gVar == null) {
                    return null;
                }
                if (!gVar.c) {
                    return null;
                }
                InputStream[] inputStreamArr = new InputStream[this.g];
                for (int i = 0; i < this.g; i++) {
                    try {
                        inputStreamArr[i] = new FileInputStream(new File(gVar.f, gVar.a + "." + i));
                    } catch (FileNotFoundException unused) {
                        for (int i2 = 0; i2 < this.g && (inputStream = inputStreamArr[i2]) != null; i2++) {
                            Charset charset = j.a;
                            try {
                                inputStream.close();
                            } catch (RuntimeException e) {
                                throw e;
                            } catch (Exception unused2) {
                            }
                        }
                        return null;
                    }
                }
                this.k++;
                this.i.append((CharSequence) ("READ " + str + '\n'));
                if (a()) {
                    this.m.submit(this.n);
                }
                return new e(inputStreamArr);
            }
            throw new IllegalArgumentException(AbstractC1475a.a("keys must match regex [a-z0-9_-]{1,120}: \"", str, "\""));
        }
        throw new IllegalStateException("cache is closed");
    }

    public final void c(String str) throws IOException {
        String strSubstring;
        int iIndexOf = str.indexOf(32);
        if (iIndexOf != -1) {
            int i = iIndexOf + 1;
            int iIndexOf2 = str.indexOf(32, i);
            if (iIndexOf2 == -1) {
                strSubstring = str.substring(i);
                if (iIndexOf == 6 && str.startsWith("REMOVE")) {
                    this.j.remove(strSubstring);
                    return;
                }
            } else {
                strSubstring = str.substring(i, iIndexOf2);
            }
            g gVar = (g) this.j.get(strSubstring);
            if (gVar == null) {
                gVar = new g(strSubstring, this.g, this.a);
                this.j.put(strSubstring, gVar);
            }
            if (iIndexOf2 != -1 && iIndexOf == 5 && str.startsWith("CLEAN")) {
                String[] strArrSplit = str.substring(iIndexOf2 + 1).split(" ");
                gVar.c = true;
                gVar.d = null;
                if (strArrSplit.length == gVar.e) {
                    for (int i2 = 0; i2 < strArrSplit.length; i2++) {
                        try {
                            gVar.b[i2] = Long.parseLong(strArrSplit[i2]);
                        } catch (NumberFormatException unused) {
                            throw new IOException("unexpected journal line: " + Arrays.toString(strArrSplit));
                        }
                    }
                    return;
                }
                throw new IOException("unexpected journal line: " + Arrays.toString(strArrSplit));
            }
            if (iIndexOf2 == -1 && iIndexOf == 5 && str.startsWith("DIRTY")) {
                gVar.d = new d(this, gVar);
                return;
            } else {
                if (iIndexOf2 != -1 || iIndexOf != 4 || !str.startsWith("READ")) {
                    throw new IOException("unexpected journal line: ".concat(str));
                }
                return;
            }
        }
        throw new IOException("unexpected journal line: ".concat(str));
    }

    public final synchronized void d(String str) {
        try {
            if (this.i != null) {
                if (o.matcher(str).matches()) {
                    g gVar = (g) this.j.get(str);
                    if (gVar != null && gVar.d == null) {
                        for (int i = 0; i < this.g; i++) {
                            File file = new File(gVar.f, gVar.a + "." + i);
                            if (file.exists() && !file.delete()) {
                                throw new IOException("failed to delete " + file);
                            }
                            long j = this.h;
                            long[] jArr = gVar.b;
                            this.h = j - jArr[i];
                            jArr[i] = 0;
                        }
                        this.k++;
                        this.i.append((CharSequence) ("REMOVE " + str + '\n'));
                        this.j.remove(str);
                        if (a()) {
                            this.m.submit(this.n);
                        }
                        return;
                    }
                    return;
                }
                throw new IllegalArgumentException(AbstractC1475a.a("keys must match regex [a-z0-9_-]{1,120}: \"", str, "\""));
            }
            throw new IllegalStateException("cache is closed");
        } finally {
        }
    }

    public final d a(String str) {
        synchronized (this) {
            try {
                if (this.i != null) {
                    if (o.matcher(str).matches()) {
                        g gVar = (g) this.j.get(str);
                        if (gVar == null) {
                            gVar = new g(str, this.g, this.a);
                            this.j.put(str, gVar);
                        } else if (gVar.d != null) {
                            return null;
                        }
                        d dVar = new d(this, gVar);
                        gVar.d = dVar;
                        this.i.write("DIRTY " + str + '\n');
                        this.i.flush();
                        return dVar;
                    }
                    throw new IllegalArgumentException("keys must match regex [a-z0-9_-]{1,120}: \"" + str + "\"");
                }
                throw new IllegalStateException("cache is closed");
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public final boolean a() {
        int i = this.k;
        return i >= 2000 && i >= this.j.size();
    }
}
