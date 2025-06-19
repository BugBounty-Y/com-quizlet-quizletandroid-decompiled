package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Build;
import android.os.ConditionVariable;
import android.os.Looper;
import android.util.Base64;
import android.util.Pair;
import dalvik.system.DexClassLoader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class Z4 {
    public final Context a;
    public ExecutorService b;
    public DexClassLoader c;
    public C1 d;
    public byte[] e;
    public final boolean g;
    public S4 j;
    public M4 k;
    public final HashMap m;
    public final V4 o;
    public volatile com.google.android.gms.ads.identifier.b f = null;
    public volatile C2384n4 h = null;
    public Future i = null;
    public boolean l = false;
    public boolean n = false;

    public Z4(Context context) {
        Context applicationContext = context.getApplicationContext();
        this.g = applicationContext != null;
        context = applicationContext != null ? applicationContext : context;
        this.a = context;
        this.m = new HashMap();
        if (this.o != null) {
            return;
        }
        this.o = new V4(context);
    }

    public static Z4 c(Context context, boolean z, S4 s4) throws Throwable {
        byte[] bArrDecode;
        int i = 2;
        int i2 = 4;
        int i3 = 0;
        Z4 z4 = new Z4(context);
        Context context2 = z4.a;
        try {
            ExecutorService executorServiceNewCachedThreadPool = Executors.newCachedThreadPool(new X4());
            z4.b = executorServiceNewCachedThreadPool;
            if (z) {
                executorServiceNewCachedThreadPool.submit(new Y4(z4, 0));
            }
            z4.b.execute(new Y4(z4, 1));
            try {
                com.google.android.gms.common.c cVar = com.google.android.gms.common.c.b;
                cVar.getClass();
                com.google.android.gms.common.c.a(context2);
                z4.l = cVar.c(context2, com.google.android.gms.common.c.a) == 0;
            } catch (Throwable unused) {
            }
            if (s4 != null) {
                z4.j = s4;
            } else if (z4.l) {
                z4.i = z4.b.submit(new androidx.core.provider.a(z4, i3, i2));
            }
            char[] cArr = AbstractC1865b5.a;
            if (Looper.myLooper() == Looper.getMainLooper()) {
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.u3)).booleanValue()) {
                    throw new IllegalStateException("Task Context initialization must not be called from the UI thread.");
                }
            }
            z4.d = new C1(i);
            try {
                try {
                    bArrDecode = Base64.decode("ZXCHn3veSKESmIQGY5dTv+Y5At4diIt6mZtYwgFH5dU=", 2);
                } catch (IllegalArgumentException e) {
                    throw new zzavs(e);
                }
            } catch (zzavs e2) {
                throw new zzawe(e2);
            }
        } catch (zzawe unused2) {
        }
        if (bArrDecode.length == 0) {
            throw new IllegalArgumentException("Unable to decode ".concat("ZXCHn3veSKESmIQGY5dTv+Y5At4diIt6mZtYwgFH5dU="));
        }
        if (bArrDecode.length != 32) {
            throw new zzavs();
        }
        byte[] bArr = new byte[16];
        ByteBuffer.wrap(bArrDecode, 4, 16).get(bArr);
        for (int i4 = 0; i4 < 16; i4++) {
            bArr[i4] = (byte) (bArr[i4] ^ 68);
        }
        z4.e = bArr;
        try {
            try {
                File cacheDir = context2.getCacheDir();
                if (cacheDir == null && (cacheDir = context2.getDir("dex", 0)) == null) {
                    throw new zzawe();
                }
                File file = new File(String.format("%s/%s.jar", cacheDir, "1743000482668"));
                if (!file.exists()) {
                    C1 c1 = z4.d;
                    byte[] bArr2 = z4.e;
                    c1.getClass();
                    byte[] bArrW = C1.w("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", bArr2);
                    file.createNewFile();
                    FileOutputStream fileOutputStream = new FileOutputStream(file);
                    if (Build.VERSION.SDK_INT >= 33) {
                        file.setReadOnly();
                    }
                    fileOutputStream.write(bArrW, 0, bArrW.length);
                    fileOutputStream.close();
                }
                z4.g(cacheDir);
                try {
                    try {
                        z4.c = new DexClassLoader(file.getAbsolutePath(), cacheDir.getAbsolutePath(), null, context2.getClassLoader());
                        z4.k = new M4(z4);
                        z4.n = true;
                        return z4;
                    } catch (SecurityException e3) {
                        throw new zzawe(e3);
                    }
                } finally {
                    h(file);
                    z4.f(cacheDir);
                    h(new File(String.format("%s/%s.dex", cacheDir, "1743000482668")));
                }
            } catch (IOException e4) {
                throw new zzawe(e4);
            } catch (NullPointerException e5) {
                throw new zzawe(e5);
            }
        } catch (zzavs e6) {
            throw new zzawe(e6);
        } catch (FileNotFoundException e7) {
            throw new zzawe(e7);
        }
    }

    public static final void h(File file) {
        if (file.exists()) {
            file.delete();
        } else {
            file.getAbsolutePath();
        }
    }

    public final int a() {
        if (this.k == null) {
            return Integer.MIN_VALUE;
        }
        ConditionVariable conditionVariable = M4.c;
        try {
            return ThreadLocalRandom.current().nextInt();
        } catch (RuntimeException unused) {
            if (M4.e == null) {
                synchronized (M4.class) {
                    try {
                        if (M4.e == null) {
                            M4.e = new Random();
                        }
                    } finally {
                    }
                }
            }
            return M4.e.nextInt();
        }
    }

    public final C2384n4 b() {
        S4 s4 = this.j;
        if (s4 == null) {
            return this.h;
        }
        RunnableFutureC2161hw runnableFutureC2161hw = (RunnableFutureC2161hw) s4.b;
        if (runnableFutureC2161hw == null || !runnableFutureC2161hw.isDone()) {
            return C2384n4.k0();
        }
        try {
            return (C2384n4) ((RunnableFutureC2161hw) this.j.b).get();
        } catch (InterruptedException | ExecutionException unused) {
            return C2384n4.k0();
        }
    }

    public final Method d(String str, String str2) {
        C2556r5 c2556r5 = (C2556r5) this.m.get(new Pair(str, str2));
        if (c2556r5 == null) {
            return null;
        }
        if (c2556r5.d != null) {
            return c2556r5.d;
        }
        try {
            if (c2556r5.f.await(2L, TimeUnit.SECONDS)) {
                return c2556r5.d;
            }
            return null;
        } catch (InterruptedException unused) {
            return null;
        }
    }

    public final void e(String str, String str2, Class... clsArr) {
        Pair pair = new Pair(str, str2);
        HashMap map = this.m;
        if (map.containsKey(pair)) {
            return;
        }
        map.put(pair, new C2556r5(this, str, str2, clsArr));
    }

    public final void f(File file) throws Throwable {
        Throwable th;
        FileOutputStream fileOutputStream;
        File file2 = new File(String.format("%s/%s.tmp", file, "1743000482668"));
        if (file2.exists()) {
            return;
        }
        File file3 = new File(String.format("%s/%s.dex", file, "1743000482668"));
        if (!file3.exists()) {
            return;
        }
        long length = file3.length();
        if (length <= 0) {
            return;
        }
        byte[] bArr = new byte[(int) length];
        FileInputStream fileInputStream = null;
        try {
            FileInputStream fileInputStream2 = new FileInputStream(file3);
            try {
                try {
                    if (fileInputStream2.read(bArr) <= 0) {
                        try {
                            fileInputStream2.close();
                        } catch (IOException unused) {
                        }
                        h(file3);
                        return;
                    }
                    System.out.print("test");
                    System.out.print("test");
                    System.out.print("test");
                    C2470p4 c2470p4W = C2513q4.w();
                    byte[] bytes = Build.VERSION.SDK.getBytes();
                    C2905zA c2905zA = BA.b;
                    c2470p4W.i(BA.w(0, bytes, bytes.length));
                    byte[] bytes2 = "1743000482668".getBytes();
                    c2470p4W.k(BA.w(0, bytes2, bytes2.length));
                    C1 c1 = this.d;
                    byte[] bArr2 = this.e;
                    c1.getClass();
                    byte[] bytes3 = C1.s(bArr2, bArr).getBytes();
                    c2470p4W.g(BA.w(0, bytes3, bytes3.length));
                    byte[] bArrC = D4.c(bytes3);
                    c2470p4W.h(BA.w(0, bArrC, bArrC.length));
                    file2.createNewFile();
                    fileOutputStream = new FileOutputStream(file2);
                    try {
                        byte[] bArrD = ((C2513q4) c2470p4W.c()).d();
                        fileOutputStream.write(bArrD, 0, bArrD.length);
                        fileOutputStream.close();
                        try {
                            fileInputStream2.close();
                        } catch (IOException unused2) {
                        }
                        try {
                            fileOutputStream.close();
                        } catch (IOException unused3) {
                        }
                        h(file3);
                    } catch (zzavs | IOException | NoSuchAlgorithmException unused4) {
                        fileInputStream = fileInputStream2;
                        if (fileInputStream != null) {
                            try {
                                fileInputStream.close();
                            } catch (IOException unused5) {
                            }
                        }
                        if (fileOutputStream != null) {
                            try {
                                fileOutputStream.close();
                            } catch (IOException unused6) {
                            }
                        }
                        h(file3);
                    } catch (Throwable th2) {
                        th = th2;
                        fileInputStream = fileInputStream2;
                        if (fileInputStream != null) {
                            try {
                                fileInputStream.close();
                            } catch (IOException unused7) {
                            }
                        }
                        if (fileOutputStream != null) {
                            try {
                                fileOutputStream.close();
                            } catch (IOException unused8) {
                            }
                        }
                        h(file3);
                        throw th;
                    }
                } catch (Throwable th3) {
                    th = th3;
                    fileOutputStream = null;
                }
            } catch (zzavs | IOException | NoSuchAlgorithmException unused9) {
                fileOutputStream = null;
            }
        } catch (zzavs | IOException | NoSuchAlgorithmException unused10) {
            fileOutputStream = null;
        } catch (Throwable th4) {
            th = th4;
            fileOutputStream = null;
        }
    }

    public final void g(File file) throws Throwable {
        FileOutputStream fileOutputStream;
        File file2 = new File(String.format("%s/%s.tmp", file, "1743000482668"));
        if (!file2.exists()) {
            return;
        }
        File file3 = new File(String.format("%s/%s.dex", file, "1743000482668"));
        if (file3.exists()) {
            return;
        }
        FileInputStream fileInputStream = null;
        try {
            try {
                long length = file2.length();
                if (length <= 0) {
                    h(file2);
                    return;
                }
                byte[] bArr = new byte[(int) length];
                FileInputStream fileInputStream2 = new FileInputStream(file2);
                try {
                    try {
                        if (fileInputStream2.read(bArr) <= 0) {
                            h(file2);
                        } else {
                            try {
                                C2513q4 c2513q4X = C2513q4.x(bArr, IA.a());
                                if ("1743000482668".equals(new String(c2513q4X.B().a())) && Arrays.equals(c2513q4X.z().a(), D4.c(c2513q4X.y().a())) && Arrays.equals(c2513q4X.A().a(), Build.VERSION.SDK.getBytes())) {
                                    C1 c1 = this.d;
                                    byte[] bArr2 = this.e;
                                    String str = new String(c2513q4X.y().a());
                                    c1.getClass();
                                    byte[] bArrW = C1.w(str, bArr2);
                                    file3.createNewFile();
                                    fileOutputStream = new FileOutputStream(file3);
                                    try {
                                        fileOutputStream.write(bArrW, 0, bArrW.length);
                                        try {
                                            fileInputStream2.close();
                                        } catch (IOException unused) {
                                        }
                                        try {
                                            fileOutputStream.close();
                                            return;
                                        } catch (IOException unused2) {
                                            return;
                                        }
                                    } catch (zzavs | IOException | NoSuchAlgorithmException unused3) {
                                        fileInputStream = fileInputStream2;
                                        if (fileInputStream != null) {
                                            try {
                                                fileInputStream.close();
                                            } catch (IOException unused4) {
                                            }
                                        }
                                        if (fileOutputStream != null) {
                                            fileOutputStream.close();
                                            return;
                                        }
                                        return;
                                    } catch (Throwable th) {
                                        th = th;
                                        fileInputStream = fileInputStream2;
                                        if (fileInputStream != null) {
                                            try {
                                                fileInputStream.close();
                                            } catch (IOException unused5) {
                                            }
                                        }
                                        if (fileOutputStream == null) {
                                            throw th;
                                        }
                                        try {
                                            fileOutputStream.close();
                                            throw th;
                                        } catch (IOException unused6) {
                                            throw th;
                                        }
                                    }
                                }
                                h(file2);
                            } catch (NullPointerException unused7) {
                                fileInputStream2.close();
                                return;
                            }
                        }
                        fileInputStream2.close();
                    } catch (Throwable th2) {
                        th = th2;
                        fileOutputStream = null;
                    }
                } catch (zzavs | IOException | NoSuchAlgorithmException unused8) {
                    fileOutputStream = null;
                }
            } catch (IOException unused9) {
            }
        } catch (zzavs | IOException | NoSuchAlgorithmException unused10) {
            fileOutputStream = null;
        } catch (Throwable th3) {
            th = th3;
            fileOutputStream = null;
        }
    }
}
