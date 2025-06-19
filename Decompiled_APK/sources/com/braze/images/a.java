package com.braze.images;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import com.braze.C1481g;
import com.braze.lrucache.j;
import com.braze.support.BrazeLogger;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3336f;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.regex.Pattern;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final com.braze.lrucache.f a;

    public a(File file) throws IOException {
        Pattern pattern = com.braze.lrucache.f.o;
        File file2 = new File(file, "journal.bkp");
        if (file2.exists()) {
            File file3 = new File(file, "journal");
            if (file3.exists()) {
                file2.delete();
            } else if (!file2.renameTo(file3)) {
                throw new IOException();
            }
        }
        com.braze.lrucache.f fVar = new com.braze.lrucache.f(file);
        if (fVar.b.exists()) {
            try {
                fVar.c();
                fVar.b();
            } catch (IOException e) {
                BrazeLogger.w(com.braze.lrucache.f.p, "DiskLruCache " + file + " is corrupt: " + e.getMessage() + ", removing");
                synchronized (fVar) {
                    try {
                        if (fVar.i != null) {
                            Iterator it2 = new ArrayList(fVar.j.values()).iterator();
                            while (it2.hasNext()) {
                                com.braze.lrucache.d dVar = ((com.braze.lrucache.g) it2.next()).d;
                                if (dVar != null) {
                                    com.braze.lrucache.f.a(dVar.d, dVar, false);
                                }
                            }
                            while (fVar.h > fVar.f) {
                                fVar.d((String) ((Map.Entry) fVar.j.entrySet().iterator().next()).getKey());
                            }
                            fVar.i.close();
                            fVar.i = null;
                        }
                        j.a(fVar.a);
                    } catch (Throwable th) {
                        throw th;
                    }
                }
            }
        } else {
            file.mkdirs();
            fVar = new com.braze.lrucache.f(file);
            fVar.d();
        }
        Intrinsics.checkNotNullExpressionValue(fVar, "open(...)");
        this.a = fVar;
    }

    public static final String c(String str, String str2) {
        return "Failed to load image from disk cache: " + str + '/' + str2;
    }

    public static final String d(String str, String str2) {
        return android.support.v4.media.session.a.m("Error while producing output stream or compressing bitmap for key ", str, " diskKey ", str2);
    }

    public final boolean a(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        String strValueOf = String.valueOf(key.hashCode());
        try {
            com.braze.lrucache.e eVarB = this.a.b(strValueOf);
            boolean z = eVarB != null;
            AbstractC3336f.c(eVarB, null);
            return z;
        } catch (Throwable th) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, th, false, (Function0) new C1481g(6, key, strValueOf), 4, (Object) null);
            return false;
        }
    }

    public final Bitmap b(String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        String strValueOf = String.valueOf(key.hashCode());
        try {
            com.braze.lrucache.e eVarB = this.a.b(strValueOf);
            try {
                Bitmap bitmapDecodeStream = BitmapFactory.decodeStream(eVarB.a[0]);
                eVarB.close();
                return bitmapDecodeStream;
            } finally {
            }
        } catch (Throwable th) {
            BrazeLogger brazeLogger = BrazeLogger.INSTANCE;
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, BrazeLogger.Priority.E, th, false, (Function0) new C1481g(8, key, strValueOf), 4, (Object) null);
            BrazeLogger.brazelog$default(brazeLogger, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new C1481g(9, key, strValueOf), 7, (Object) null);
            return null;
        }
    }

    public static final String a(String str, String str2) {
        return android.support.v4.media.session.a.m("Error while retrieving disk for key ", str, " diskKey ", str2);
    }

    public static final String b(String str, String str2) {
        return android.support.v4.media.session.a.m("Failed to get bitmap from disk cache for key ", str, " diskKey ", str2);
    }

    public final void a(String key, Bitmap bitmap) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(bitmap, "bitmap");
        String strValueOf = String.valueOf(key.hashCode());
        try {
            com.braze.lrucache.d dVarA = this.a.a(strValueOf);
            OutputStream outputStreamA = dVarA.a();
            try {
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, outputStreamA);
                outputStreamA.flush();
                Unit unit = Unit.a;
                outputStreamA.close();
                if (dVarA.c) {
                    com.braze.lrucache.f.a(dVarA.d, dVarA, false);
                    dVarA.d.d(dVarA.a.a);
                } else {
                    com.braze.lrucache.f.a(dVarA.d, dVarA, true);
                }
            } finally {
            }
        } catch (Throwable th) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, th, false, (Function0) new C1481g(7, key, strValueOf), 4, (Object) null);
        }
    }
}
