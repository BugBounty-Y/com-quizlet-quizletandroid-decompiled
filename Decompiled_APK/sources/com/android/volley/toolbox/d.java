package com.android.volley.toolbox;

import android.os.SystemClock;
import android.text.TextUtils;
import androidx.compose.animation.d0;
import com.android.volley.y;
import com.google.android.gms.internal.ads.C1732Mb;
import com.google.android.gms.internal.ads.C2683u3;
import com.google.android.gms.internal.ads.C2812x3;
import com.google.android.gms.internal.ads.C2881yn;
import com.google.android.gms.internal.ads.H3;
import com.google.android.gms.internal.ads.J3;
import com.google.android.gms.internal.ads.K3;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/* loaded from: classes.dex */
public final class d implements com.android.volley.b {
    public final Serializable a;
    public long b;
    public final int c;
    public final Object d;

    public d(int i, long j, String str, String str2) {
        this.b = j;
        this.a = str;
        this.d = str2;
        this.c = i;
    }

    public static int A(c cVar) throws IOException {
        int i = cVar.read();
        if (i != -1) {
            return i;
        }
        throw new EOFException();
    }

    public static final String C(String str) {
        int length = str.length() / 2;
        return String.valueOf(String.valueOf(str.substring(0, length).hashCode())).concat(String.valueOf(String.valueOf(str.substring(length).hashCode())));
    }

    public static String c(String str) {
        int length = str.length() / 2;
        StringBuilder sbU = d0.u(String.valueOf(str.substring(0, length).hashCode()));
        sbU.append(String.valueOf(str.substring(length).hashCode()));
        return sbU.toString();
    }

    public static int h(c cVar) throws IOException {
        int i = cVar.read();
        if (i != -1) {
            return i;
        }
        throw new EOFException();
    }

    public static int i(c cVar) {
        return (h(cVar) << 24) | h(cVar) | (h(cVar) << 8) | (h(cVar) << 16);
    }

    public static long j(c cVar) {
        return (h(cVar) & 255) | ((h(cVar) & 255) << 8) | ((h(cVar) & 255) << 16) | ((h(cVar) & 255) << 24) | ((h(cVar) & 255) << 32) | ((h(cVar) & 255) << 40) | ((h(cVar) & 255) << 48) | ((255 & h(cVar)) << 56);
    }

    public static String k(c cVar) {
        return new String(l(cVar, j(cVar)), "UTF-8");
    }

    public static byte[] l(c cVar, long j) throws IOException {
        long j2 = cVar.b - cVar.c;
        if (j >= 0 && j <= j2) {
            int i = (int) j;
            if (i == j) {
                byte[] bArr = new byte[i];
                new DataInputStream(cVar).readFully(bArr);
                return bArr;
            }
        }
        StringBuilder sbT = d0.t(j, "streamToBytes length=", ", maxLength=");
        sbT.append(j2);
        throw new IOException(sbT.toString());
    }

    public static void m(BufferedOutputStream bufferedOutputStream, int i) {
        bufferedOutputStream.write(i & 255);
        bufferedOutputStream.write((i >> 8) & 255);
        bufferedOutputStream.write((i >> 16) & 255);
        bufferedOutputStream.write((i >> 24) & 255);
    }

    public static void n(BufferedOutputStream bufferedOutputStream, long j) {
        bufferedOutputStream.write((byte) j);
        bufferedOutputStream.write((byte) (j >>> 8));
        bufferedOutputStream.write((byte) (j >>> 16));
        bufferedOutputStream.write((byte) (j >>> 24));
        bufferedOutputStream.write((byte) (j >>> 32));
        bufferedOutputStream.write((byte) (j >>> 40));
        bufferedOutputStream.write((byte) (j >>> 48));
        bufferedOutputStream.write((byte) (j >>> 56));
    }

    public static void o(BufferedOutputStream bufferedOutputStream, String str) {
        byte[] bytes = str.getBytes("UTF-8");
        n(bufferedOutputStream, bytes.length);
        bufferedOutputStream.write(bytes, 0, bytes.length);
    }

    public static int s(c cVar) {
        return (A(cVar) << 24) | A(cVar) | (A(cVar) << 8) | (A(cVar) << 16);
    }

    public static long t(c cVar) {
        return (A(cVar) & 255) | ((A(cVar) & 255) << 8) | ((A(cVar) & 255) << 16) | ((A(cVar) & 255) << 24) | ((A(cVar) & 255) << 32) | ((A(cVar) & 255) << 40) | ((A(cVar) & 255) << 48) | ((A(cVar) & 255) << 56);
    }

    public static String v(c cVar) {
        return new String(z(cVar, t(cVar)), "UTF-8");
    }

    public static void w(BufferedOutputStream bufferedOutputStream, int i) throws IOException {
        bufferedOutputStream.write(i & 255);
        bufferedOutputStream.write((i >> 8) & 255);
        bufferedOutputStream.write((i >> 16) & 255);
        bufferedOutputStream.write((i >> 24) & 255);
    }

    public static void x(BufferedOutputStream bufferedOutputStream, long j) throws IOException {
        bufferedOutputStream.write((byte) j);
        bufferedOutputStream.write((byte) (j >>> 8));
        bufferedOutputStream.write((byte) (j >>> 16));
        bufferedOutputStream.write((byte) (j >>> 24));
        bufferedOutputStream.write((byte) (j >>> 32));
        bufferedOutputStream.write((byte) (j >>> 40));
        bufferedOutputStream.write((byte) (j >>> 48));
        bufferedOutputStream.write((byte) (j >>> 56));
    }

    public static void y(BufferedOutputStream bufferedOutputStream, String str) throws IOException {
        byte[] bytes = str.getBytes("UTF-8");
        int length = bytes.length;
        x(bufferedOutputStream, length);
        bufferedOutputStream.write(bytes, 0, length);
    }

    public static byte[] z(c cVar, long j) throws IOException {
        long j2 = cVar.b - cVar.c;
        if (j >= 0 && j <= j2) {
            int i = (int) j;
            if (i == j) {
                byte[] bArr = new byte[i];
                new DataInputStream(cVar).readFully(bArr);
                return bArr;
            }
        }
        StringBuilder sbT = d0.t(j, "streamToBytes length=", ", maxLength=");
        sbT.append(j2);
        throw new IOException(sbT.toString());
    }

    public void B(String str, J3 j3) {
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.a;
        if (linkedHashMap.containsKey(str)) {
            this.b = (j3.a - ((J3) linkedHashMap.get(str)).a) + this.b;
        } else {
            this.b += j3.a;
        }
        linkedHashMap.put(str, j3);
    }

    public synchronized com.android.volley.a a(String str) {
        b bVar = (b) ((LinkedHashMap) this.a).get(str);
        if (bVar == null) {
            return null;
        }
        File fileB = b(str);
        try {
            c cVar = new c(new BufferedInputStream(new FileInputStream(fileB)), fileB.length(), 0);
            try {
                b bVarA = b.a(cVar);
                if (TextUtils.equals(str, bVarA.b)) {
                    return bVar.b(l(cVar, cVar.b - cVar.c));
                }
                y.a("%s: key=%s, found=%s", fileB.getAbsolutePath(), str, bVarA.b);
                b bVar2 = (b) ((LinkedHashMap) this.a).remove(str);
                if (bVar2 != null) {
                    this.b -= bVar2.a;
                }
                return null;
            } finally {
                cVar.close();
            }
        } catch (IOException e) {
            y.a("%s: %s", fileB.getAbsolutePath(), e.toString());
            synchronized (this) {
                boolean zDelete = b(str).delete();
                b bVar3 = (b) ((LinkedHashMap) this.a).remove(str);
                if (bVar3 != null) {
                    this.b -= bVar3.a;
                }
                if (!zDelete) {
                    y.a("Could not delete cache entry for key=%s, filename=%s", str, c(str));
                }
                return null;
            }
        }
    }

    public File b(String str) {
        return new File((File) ((com.google.android.gms.internal.instantapps.a) this.d).b, c(str));
    }

    public synchronized void d() {
        File file = (File) ((com.google.android.gms.internal.instantapps.a) this.d).b;
        if (!file.exists()) {
            if (!file.mkdirs()) {
                y.b("Unable to create cache dir %s", file.getAbsolutePath());
            }
            return;
        }
        File[] fileArrListFiles = file.listFiles();
        if (fileArrListFiles == null) {
            return;
        }
        for (File file2 : fileArrListFiles) {
            try {
                long length = file2.length();
                c cVar = new c(new BufferedInputStream(new FileInputStream(file2)), length, 0);
                try {
                    b bVarA = b.a(cVar);
                    bVarA.a = length;
                    g(bVarA.b, bVarA);
                    cVar.close();
                } catch (Throwable th) {
                    cVar.close();
                    throw th;
                }
            } catch (IOException unused) {
                file2.delete();
            }
        }
    }

    public void e() {
        long j = this.b;
        int i = this.c;
        if (j < i) {
            return;
        }
        int i2 = 0;
        if (y.a) {
            y.c("Pruning old cache entries.", new Object[0]);
        }
        long j2 = this.b;
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        Iterator it2 = ((LinkedHashMap) this.a).entrySet().iterator();
        while (it2.hasNext()) {
            b bVar = (b) ((Map.Entry) it2.next()).getValue();
            if (b(bVar.b).delete()) {
                this.b -= bVar.a;
            } else {
                String str = bVar.b;
                y.a("Could not delete cache entry for key=%s, filename=%s", str, c(str));
            }
            it2.remove();
            i2++;
            if (this.b < i * 0.9f) {
                break;
            }
        }
        if (y.a) {
            y.c("pruned %d files, %d bytes, %d ms", Integer.valueOf(i2), Long.valueOf(this.b - j2), Long.valueOf(SystemClock.elapsedRealtime() - jElapsedRealtime));
        }
    }

    public synchronized void f(String str, com.android.volley.a aVar) {
        BufferedOutputStream bufferedOutputStream;
        b bVar;
        long j = this.b;
        byte[] bArr = aVar.a;
        long length = j + bArr.length;
        int i = this.c;
        if (length <= i || bArr.length <= i * 0.9f) {
            File fileB = b(str);
            try {
                bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(fileB));
                bVar = new b(str, aVar);
            } catch (IOException unused) {
                if (!fileB.delete()) {
                    y.a("Could not clean up file %s", fileB.getAbsolutePath());
                }
                if (!((File) ((com.google.android.gms.internal.instantapps.a) this.d).b).exists()) {
                    y.a("Re-initializing cache after external clearing.", new Object[0]);
                    ((LinkedHashMap) this.a).clear();
                    this.b = 0L;
                    d();
                }
            }
            if (!bVar.c(bufferedOutputStream)) {
                bufferedOutputStream.close();
                y.a("Failed to write header for %s", fileB.getAbsolutePath());
                throw new IOException();
            }
            bufferedOutputStream.write(aVar.a);
            bufferedOutputStream.close();
            bVar.a = fileB.length();
            g(str, bVar);
            e();
        }
    }

    public void g(String str, b bVar) {
        LinkedHashMap linkedHashMap = (LinkedHashMap) this.a;
        if (linkedHashMap.containsKey(str)) {
            this.b = (bVar.a - ((b) linkedHashMap.get(str)).a) + this.b;
        } else {
            this.b += bVar.a;
        }
        linkedHashMap.put(str, bVar);
    }

    public synchronized C2683u3 p(String str) {
        J3 j3 = (J3) ((LinkedHashMap) this.a).get(str);
        if (j3 == null) {
            return null;
        }
        File fileU = u(str);
        try {
            c cVar = new c(new BufferedInputStream(new FileInputStream(fileU)), fileU.length(), 1);
            try {
                String str2 = J3.a(cVar).b;
                if (!TextUtils.equals(str, str2)) {
                    H3.c("%s: key=%s, found=%s", fileU.getAbsolutePath(), str, str2);
                    J3 j32 = (J3) ((LinkedHashMap) this.a).remove(str);
                    if (j32 != null) {
                        this.b -= j32.a;
                    }
                    return null;
                }
                byte[] bArrZ = z(cVar, cVar.b - cVar.c);
                C2683u3 c2683u3 = new C2683u3();
                c2683u3.a = bArrZ;
                c2683u3.b = j3.c;
                c2683u3.c = j3.d;
                c2683u3.d = j3.e;
                c2683u3.e = j3.f;
                c2683u3.f = j3.g;
                List<C2812x3> list = j3.h;
                TreeMap treeMap = new TreeMap(String.CASE_INSENSITIVE_ORDER);
                for (C2812x3 c2812x3 : list) {
                    treeMap.put(c2812x3.a, c2812x3.b);
                }
                c2683u3.g = treeMap;
                c2683u3.h = Collections.unmodifiableList(list);
                return c2683u3;
            } finally {
                cVar.close();
            }
        } catch (IOException e) {
            H3.c("%s: %s", fileU.getAbsolutePath(), e.toString());
            synchronized (this) {
                boolean zDelete = u(str).delete();
                J3 j33 = (J3) ((LinkedHashMap) this.a).remove(str);
                if (j33 != null) {
                    this.b -= j33.a;
                }
                if (!zDelete) {
                    H3.c("Could not delete cache entry for key=%s, filename=%s", str, C(str));
                }
                return null;
            }
        }
    }

    public synchronized void q() {
        long length;
        c cVar;
        File fileMo18zza = ((K3) this.d).mo18zza();
        if (fileMo18zza.exists()) {
            File[] fileArrListFiles = fileMo18zza.listFiles();
            if (fileArrListFiles != null) {
                for (File file : fileArrListFiles) {
                    try {
                        length = file.length();
                        cVar = new c(new BufferedInputStream(new FileInputStream(file)), length, 1);
                    } catch (IOException unused) {
                        file.delete();
                    }
                    try {
                        J3 j3A = J3.a(cVar);
                        j3A.a = length;
                        B(j3A.b, j3A);
                        cVar.close();
                    } catch (Throwable th) {
                        cVar.close();
                        throw th;
                    }
                }
            }
        } else if (!fileMo18zza.mkdirs()) {
            H3.a("Unable to create cache dir %s", fileMo18zza.getAbsolutePath());
        }
    }

    public synchronized void r(String str, C2683u3 c2683u3) {
        float f;
        try {
            long j = this.b;
            int length = c2683u3.a.length;
            long j2 = j + length;
            int i = this.c;
            float f2 = 0.9f;
            if (j2 <= i || length <= i * 0.9f) {
                File fileU = u(str);
                try {
                    BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(fileU));
                    J3 j3 = new J3(str, c2683u3);
                    try {
                        w(bufferedOutputStream, 538247942);
                        y(bufferedOutputStream, str);
                        String str2 = j3.c;
                        if (str2 == null) {
                            str2 = "";
                        }
                        y(bufferedOutputStream, str2);
                        x(bufferedOutputStream, j3.d);
                        x(bufferedOutputStream, j3.e);
                        x(bufferedOutputStream, j3.f);
                        x(bufferedOutputStream, j3.g);
                        List<C2812x3> list = j3.h;
                        if (list != null) {
                            w(bufferedOutputStream, list.size());
                            for (C2812x3 c2812x3 : list) {
                                y(bufferedOutputStream, c2812x3.a);
                                y(bufferedOutputStream, c2812x3.b);
                            }
                        } else {
                            w(bufferedOutputStream, 0);
                        }
                        bufferedOutputStream.flush();
                        bufferedOutputStream.write(c2683u3.a);
                        bufferedOutputStream.close();
                        j3.a = fileU.length();
                        B(str, j3);
                        long j4 = this.b;
                        int i2 = this.c;
                        if (j4 >= i2) {
                            boolean z = H3.a;
                            if (z) {
                                H3.b("Pruning old cache entries.", new Object[0]);
                            }
                            long j5 = this.b;
                            long jElapsedRealtime = SystemClock.elapsedRealtime();
                            Iterator it2 = ((LinkedHashMap) this.a).entrySet().iterator();
                            int i3 = 0;
                            while (it2.hasNext()) {
                                J3 j32 = (J3) ((Map.Entry) it2.next()).getValue();
                                String str3 = j32.b;
                                if (u(str3).delete()) {
                                    f = f2;
                                    this.b -= j32.a;
                                } else {
                                    f = f2;
                                    H3.c("Could not delete cache entry for key=%s, filename=%s", str3, C(str3));
                                }
                                it2.remove();
                                i3++;
                                if (this.b < i2 * f) {
                                    break;
                                } else {
                                    f2 = f;
                                }
                            }
                            if (z) {
                                H3.b("pruned %d files, %d bytes, %d ms", Integer.valueOf(i3), Long.valueOf(this.b - j5), Long.valueOf(SystemClock.elapsedRealtime() - jElapsedRealtime));
                            }
                        }
                    } catch (IOException e) {
                        H3.c("%s", e.toString());
                        bufferedOutputStream.close();
                        H3.c("Failed to write header for %s", fileU.getAbsolutePath());
                        throw new IOException();
                    }
                } catch (IOException unused) {
                    if (!fileU.delete()) {
                        H3.c("Could not clean up file %s", fileU.getAbsolutePath());
                    }
                    if (!((K3) this.d).mo18zza().exists()) {
                        H3.c("Re-initializing cache after external clearing.", new Object[0]);
                        ((LinkedHashMap) this.a).clear();
                        this.b = 0L;
                        q();
                    }
                }
            }
        } finally {
        }
    }

    public File u(String str) {
        return new File(((K3) this.d).mo18zza(), C(str));
    }

    public d(C1732Mb c1732Mb) {
        this.a = new LinkedHashMap(16, 0.75f, true);
        this.b = 0L;
        this.d = c1732Mb;
        this.c = 5242880;
    }

    public d(File file, int i) {
        switch (i) {
            case 1:
                this.a = new LinkedHashMap(16, 0.75f, true);
                this.b = 0L;
                this.d = new C2881yn(file, 4);
                this.c = 20971520;
                break;
            default:
                this.a = new LinkedHashMap(16, 0.75f, true);
                this.b = 0L;
                this.d = new com.google.android.gms.internal.instantapps.a(file, 19);
                this.c = 5242880;
                break;
        }
    }
}
