package com.airbnb.lottie;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Typeface;
import android.util.Base64;
import io.ktor.client.plugins.C4864k;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.zip.GZIPInputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import okio.AbstractC5085b;

/* loaded from: classes.dex */
public abstract class l {
    public static final HashMap a = new HashMap();
    public static final HashSet b = new HashSet();
    public static final byte[] c = {80, 75, 3, 4};
    public static final byte[] d = {31, -117, 8};

    public static A a(final String str, Callable callable, Runnable runnable) {
        h hVarA = str == null ? null : com.airbnb.lottie.model.g.b.a(str);
        A a2 = hVarA != null ? new A(hVarA) : null;
        HashMap map = a;
        if (str != null && map.containsKey(str)) {
            a2 = (A) map.get(str);
        }
        if (a2 != null) {
            if (runnable != null) {
                runnable.run();
            }
            return a2;
        }
        A a3 = new A(callable, false);
        if (str != null) {
            final AtomicBoolean atomicBoolean = new AtomicBoolean(false);
            final int i = 0;
            a3.b(new x() { // from class: com.airbnb.lottie.j
                @Override // com.airbnb.lottie.x
                public final void onResult(Object obj) {
                    switch (i) {
                        case 0:
                            HashMap map2 = l.a;
                            map2.remove(str);
                            atomicBoolean.set(true);
                            if (map2.size() == 0) {
                                l.k();
                                break;
                            }
                            break;
                        default:
                            HashMap map3 = l.a;
                            map3.remove(str);
                            atomicBoolean.set(true);
                            if (map3.size() == 0) {
                                l.k();
                                break;
                            }
                            break;
                    }
                }
            });
            final int i2 = 1;
            a3.a(new x() { // from class: com.airbnb.lottie.j
                @Override // com.airbnb.lottie.x
                public final void onResult(Object obj) {
                    switch (i2) {
                        case 0:
                            HashMap map2 = l.a;
                            map2.remove(str);
                            atomicBoolean.set(true);
                            if (map2.size() == 0) {
                                l.k();
                                break;
                            }
                            break;
                        default:
                            HashMap map3 = l.a;
                            map3.remove(str);
                            atomicBoolean.set(true);
                            if (map3.size() == 0) {
                                l.k();
                                break;
                            }
                            break;
                    }
                }
            });
            if (!atomicBoolean.get()) {
                map.put(str, a3);
                if (map.size() == 1) {
                    k();
                }
            }
        }
        return a3;
    }

    public static z b(Context context, String str, String str2) {
        h hVarA = str2 == null ? null : com.airbnb.lottie.model.g.b.a(str2);
        if (hVarA != null) {
            return new z(hVarA);
        }
        try {
            return c(context, context.getAssets().open(str), str2);
        } catch (IOException e) {
            return new z(e);
        }
    }

    public static z c(Context context, InputStream inputStream, String str) {
        int i = 3;
        h hVarA = str == null ? null : com.airbnb.lottie.model.g.b.a(str);
        if (hVarA != null) {
            return new z(hVarA);
        }
        try {
            okio.A aC = AbstractC5085b.c(AbstractC5085b.j(inputStream));
            if (j(aC, c).booleanValue()) {
                return h(context, new ZipInputStream(new C4864k(aC, i)), str);
            }
            if (j(aC, d).booleanValue()) {
                return d(new GZIPInputStream(new C4864k(aC, i)), str);
            }
            String[] strArr = com.airbnb.lottie.parser.moshi.d.e;
            return e(new com.airbnb.lottie.parser.moshi.e(aC), str, true);
        } catch (IOException e) {
            return new z(e);
        }
    }

    public static z d(InputStream inputStream, String str) {
        okio.A aC = AbstractC5085b.c(AbstractC5085b.j(inputStream));
        String[] strArr = com.airbnb.lottie.parser.moshi.d.e;
        return e(new com.airbnb.lottie.parser.moshi.e(aC), str, true);
    }

    public static z e(com.airbnb.lottie.parser.moshi.e eVar, String str, boolean z) throws IOException {
        h hVarA;
        try {
            if (str == null) {
                hVarA = null;
            } else {
                try {
                    hVarA = com.airbnb.lottie.model.g.b.a(str);
                } catch (Exception e) {
                    z zVar = new z(e);
                    if (z) {
                        com.airbnb.lottie.utils.i.b(eVar);
                    }
                    return zVar;
                }
            }
            if (hVarA != null) {
                z zVar2 = new z(hVarA);
                if (z) {
                    com.airbnb.lottie.utils.i.b(eVar);
                }
                return zVar2;
            }
            h hVarA2 = com.airbnb.lottie.parser.s.a(eVar);
            if (str != null) {
                com.airbnb.lottie.model.g.b.a.k(str, hVarA2);
            }
            z zVar3 = new z(hVarA2);
            if (z) {
                com.airbnb.lottie.utils.i.b(eVar);
            }
            return zVar3;
        } catch (Throwable th) {
            if (z) {
                com.airbnb.lottie.utils.i.b(eVar);
            }
            throw th;
        }
    }

    public static A f(Context context, final String str, final int i) {
        final WeakReference weakReference = new WeakReference(context);
        final Context applicationContext = context.getApplicationContext();
        return a(str, new Callable() { // from class: com.airbnb.lottie.k
            @Override // java.util.concurrent.Callable
            public final Object call() {
                Context context2 = (Context) weakReference.get();
                if (context2 == null) {
                    context2 = applicationContext;
                }
                return l.g(context2, str, i);
            }
        }, null);
    }

    public static z g(Context context, String str, int i) {
        int i2 = 3;
        h hVarA = str == null ? null : com.airbnb.lottie.model.g.b.a(str);
        if (hVarA != null) {
            return new z(hVarA);
        }
        try {
            okio.A aC = AbstractC5085b.c(AbstractC5085b.j(context.getResources().openRawResource(i)));
            if (j(aC, c).booleanValue()) {
                return h(context, new ZipInputStream(new C4864k(aC, i2)), str);
            }
            if (!j(aC, d).booleanValue()) {
                String[] strArr = com.airbnb.lottie.parser.moshi.d.e;
                return e(new com.airbnb.lottie.parser.moshi.e(aC), str, true);
            }
            try {
                return d(new GZIPInputStream(new C4864k(aC, i2)), str);
            } catch (IOException e) {
                return new z(e);
            }
        } catch (Resources.NotFoundException e2) {
            return new z(e2);
        }
    }

    public static z h(Context context, ZipInputStream zipInputStream, String str) {
        try {
            return i(context, zipInputStream, str);
        } finally {
            com.airbnb.lottie.utils.i.b(zipInputStream);
        }
    }

    public static z i(Context context, ZipInputStream zipInputStream, String str) throws IOException {
        h hVarA;
        w wVar;
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        if (str == null) {
            hVarA = null;
        } else {
            try {
                hVarA = com.airbnb.lottie.model.g.b.a(str);
            } catch (IOException e) {
                return new z(e);
            }
        }
        if (hVarA != null) {
            return new z(hVarA);
        }
        ZipEntry nextEntry = zipInputStream.getNextEntry();
        h hVar = null;
        while (nextEntry != null) {
            String name = nextEntry.getName();
            if (name.contains("__MACOSX")) {
                zipInputStream.closeEntry();
            } else if (nextEntry.getName().equalsIgnoreCase("manifest.json")) {
                zipInputStream.closeEntry();
            } else if (nextEntry.getName().contains(".json")) {
                okio.A aC = AbstractC5085b.c(AbstractC5085b.j(zipInputStream));
                String[] strArr = com.airbnb.lottie.parser.moshi.d.e;
                hVar = e(new com.airbnb.lottie.parser.moshi.e(aC), null, false).a;
            } else if (name.contains(".png") || name.contains(".webp") || name.contains(".jpg") || name.contains(".jpeg")) {
                String[] strArrSplit = name.split("/");
                map.put(strArrSplit[strArrSplit.length - 1], BitmapFactory.decodeStream(zipInputStream));
            } else if (name.contains(".ttf") || name.contains(".otf")) {
                String[] strArrSplit2 = name.split("/");
                String str2 = strArrSplit2[strArrSplit2.length - 1];
                String str3 = str2.split("\\.")[0];
                if (context == null) {
                    return new z(new IllegalStateException("Unable to extract font " + str3 + " please pass a non-null Context parameter"));
                }
                File file = new File(context.getCacheDir(), str2);
                try {
                    FileOutputStream fileOutputStream = new FileOutputStream(file);
                    try {
                        FileOutputStream fileOutputStream2 = new FileOutputStream(file);
                        try {
                            byte[] bArr = new byte[4096];
                            while (true) {
                                int i = zipInputStream.read(bArr);
                                if (i == -1) {
                                    break;
                                }
                                fileOutputStream2.write(bArr, 0, i);
                            }
                            fileOutputStream2.flush();
                            fileOutputStream2.close();
                            fileOutputStream.close();
                        } catch (Throwable th) {
                            try {
                                fileOutputStream2.close();
                            } catch (Throwable th2) {
                                th.addSuppressed(th2);
                            }
                            throw th;
                        }
                    } finally {
                    }
                } catch (Throwable th3) {
                    com.airbnb.lottie.utils.c.c("Unable to save font " + str3 + " to the temporary file: " + str2 + ". ", th3);
                }
                Typeface typefaceCreateFromFile = Typeface.createFromFile(file);
                if (!file.delete()) {
                    com.airbnb.lottie.utils.c.b("Failed to delete temp font file " + file.getAbsolutePath() + ".");
                }
                map2.put(str3, typefaceCreateFromFile);
            } else {
                zipInputStream.closeEntry();
            }
            nextEntry = zipInputStream.getNextEntry();
        }
        if (hVar == null) {
            return new z(new IllegalArgumentException("Unable to parse composition"));
        }
        for (Map.Entry entry : map.entrySet()) {
            String str4 = (String) entry.getKey();
            Iterator it2 = ((HashMap) hVar.c()).values().iterator();
            while (true) {
                if (!it2.hasNext()) {
                    wVar = null;
                    break;
                }
                wVar = (w) it2.next();
                if (wVar.d.equals(str4)) {
                    break;
                }
            }
            if (wVar != null) {
                wVar.f = com.airbnb.lottie.utils.i.d((Bitmap) entry.getValue(), wVar.a, wVar.b);
            }
        }
        for (Map.Entry entry2 : map2.entrySet()) {
            boolean z = false;
            for (com.airbnb.lottie.model.c cVar : hVar.f.values()) {
                if (cVar.a.equals(entry2.getKey())) {
                    cVar.d = (Typeface) entry2.getValue();
                    z = true;
                }
            }
            if (!z) {
                com.airbnb.lottie.utils.c.b("Parsed font for " + ((String) entry2.getKey()) + " however it was not found in the animation.");
            }
        }
        if (map.isEmpty()) {
            Iterator it3 = ((HashMap) hVar.c()).entrySet().iterator();
            while (it3.hasNext()) {
                w wVar2 = (w) ((Map.Entry) it3.next()).getValue();
                if (wVar2 == null) {
                    return null;
                }
                BitmapFactory.Options options = new BitmapFactory.Options();
                options.inScaled = true;
                options.inDensity = 160;
                String str5 = wVar2.d;
                if (str5.startsWith("data:") && str5.indexOf("base64,") > 0) {
                    try {
                        byte[] bArrDecode = Base64.decode(str5.substring(str5.indexOf(44) + 1), 0);
                        Bitmap bitmapDecodeByteArray = BitmapFactory.decodeByteArray(bArrDecode, 0, bArrDecode.length, options);
                        if (bitmapDecodeByteArray != null) {
                            wVar2.f = com.airbnb.lottie.utils.i.d(bitmapDecodeByteArray, wVar2.a, wVar2.b);
                        }
                    } catch (IllegalArgumentException e2) {
                        com.airbnb.lottie.utils.c.c("data URL did not have correct base64 format.", e2);
                        return null;
                    }
                }
            }
        }
        if (str != null) {
            com.airbnb.lottie.model.g.b.a.k(str, hVar);
        }
        return new z(hVar);
    }

    public static Boolean j(okio.A a2, byte[] bArr) {
        try {
            okio.A aPeek = a2.peek();
            for (byte b2 : bArr) {
                if (aPeek.readByte() != b2) {
                    return Boolean.FALSE;
                }
            }
            aPeek.close();
            return Boolean.TRUE;
        } catch (Exception unused) {
            com.airbnb.lottie.utils.c.a.getClass();
            return Boolean.FALSE;
        } catch (NoSuchMethodError unused2) {
            return Boolean.FALSE;
        }
    }

    public static void k() {
        ArrayList arrayList = new ArrayList(b);
        if (arrayList.size() <= 0) {
            return;
        }
        arrayList.get(0).getClass();
        throw new ClassCastException();
    }

    public static String l(Context context, int i) {
        StringBuilder sb = new StringBuilder("rawRes");
        sb.append((context.getResources().getConfiguration().uiMode & 48) == 32 ? "_night_" : "_day_");
        sb.append(i);
        return sb.toString();
    }
}
