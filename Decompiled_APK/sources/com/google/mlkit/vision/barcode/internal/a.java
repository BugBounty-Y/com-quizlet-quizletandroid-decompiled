package com.google.mlkit.vision.barcode.internal;

import android.content.Context;
import android.util.SparseArray;
import com.google.android.gms.internal.mlkit_vision_barcode.B;
import com.google.android.gms.internal.mlkit_vision_barcode.D7;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3290w5;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3298x5;
import com.google.android.gms.internal.mlkit_vision_barcode.G5;
import com.google.android.gms.internal.mlkit_vision_barcode.H5;
import com.google.android.gms.internal.mlkit_vision_barcode.J7;
import java.util.HashMap;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public abstract class a {
    public static final SparseArray a;
    public static final SparseArray b;
    public static final AtomicReference c;
    public static final HashMap d;

    static {
        SparseArray sparseArray = new SparseArray();
        a = sparseArray;
        SparseArray sparseArray2 = new SparseArray();
        b = sparseArray2;
        c = new AtomicReference();
        sparseArray.put(-1, G5.FORMAT_UNKNOWN);
        sparseArray.put(1, G5.FORMAT_CODE_128);
        sparseArray.put(2, G5.FORMAT_CODE_39);
        sparseArray.put(4, G5.FORMAT_CODE_93);
        sparseArray.put(8, G5.FORMAT_CODABAR);
        sparseArray.put(16, G5.FORMAT_DATA_MATRIX);
        sparseArray.put(32, G5.FORMAT_EAN_13);
        sparseArray.put(64, G5.FORMAT_EAN_8);
        sparseArray.put(128, G5.FORMAT_ITF);
        sparseArray.put(256, G5.FORMAT_QR_CODE);
        sparseArray.put(com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH, G5.FORMAT_UPC_A);
        sparseArray.put(1024, G5.FORMAT_UPC_E);
        sparseArray.put(2048, G5.FORMAT_PDF417);
        sparseArray.put(4096, G5.FORMAT_AZTEC);
        sparseArray2.put(0, H5.TYPE_UNKNOWN);
        sparseArray2.put(1, H5.TYPE_CONTACT_INFO);
        sparseArray2.put(2, H5.TYPE_EMAIL);
        sparseArray2.put(3, H5.TYPE_ISBN);
        sparseArray2.put(4, H5.TYPE_PHONE);
        sparseArray2.put(5, H5.TYPE_PRODUCT);
        sparseArray2.put(6, H5.TYPE_SMS);
        sparseArray2.put(7, H5.TYPE_TEXT);
        sparseArray2.put(8, H5.TYPE_URL);
        sparseArray2.put(9, H5.TYPE_WIFI);
        sparseArray2.put(10, H5.TYPE_GEO);
        sparseArray2.put(11, H5.TYPE_CALENDAR_EVENT);
        sparseArray2.put(12, H5.TYPE_DRIVER_LICENSE);
        HashMap map = new HashMap();
        d = map;
        map.put(1, D7.CODE_128);
        map.put(2, D7.CODE_39);
        map.put(4, D7.CODE_93);
        map.put(8, D7.CODABAR);
        map.put(16, D7.DATA_MATRIX);
        map.put(32, D7.EAN_13);
        map.put(64, D7.EAN_8);
        map.put(128, D7.ITF);
        map.put(256, D7.QR_CODE);
        map.put(Integer.valueOf(com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH), D7.UPC_A);
        map.put(1024, D7.UPC_E);
        map.put(2048, D7.PDF417);
        map.put(4096, D7.AZTEC);
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x0035  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.mlkit_vision_barcode.E7 a(com.google.mlkit.vision.barcode.b r4) {
        /*
            int r4 = r4.a
            com.google.android.gms.internal.mlkit_vision_barcode.u r0 = new com.google.android.gms.internal.mlkit_vision_barcode.u
            r1 = 0
            r0.<init>(r1)
            java.util.HashMap r1 = com.google.mlkit.vision.barcode.internal.a.d
            if (r4 != 0) goto L47
            java.util.Collection r4 = r1.values()
            java.util.Collection r4 = (java.util.Collection) r4
            boolean r1 = r4 instanceof java.util.Collection
            if (r1 == 0) goto L35
            r1 = r4
            java.util.Collection r1 = (java.util.Collection) r1
            int r2 = r0.b
            int r3 = r1.size()
            int r3 = r3 + r2
            r0.g(r3)
            boolean r2 = r1 instanceof com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s
            if (r2 != 0) goto L28
            goto L35
        L28:
            com.google.android.gms.internal.mlkit_vision_barcode.s r1 = (com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3252s) r1
            java.lang.Object[] r4 = r0.a
            int r2 = r0.b
            int r4 = r1.a(r4, r2)
            r0.b = r4
            goto L72
        L35:
            java.util.Iterator r4 = r4.iterator()
        L39:
            boolean r1 = r4.hasNext()
            if (r1 == 0) goto L72
            java.lang.Object r1 = r4.next()
            r0.f(r1)
            goto L39
        L47:
            java.util.Set r1 = r1.entrySet()
            java.util.Iterator r1 = r1.iterator()
        L4f:
            boolean r2 = r1.hasNext()
            if (r2 == 0) goto L72
            java.lang.Object r2 = r1.next()
            java.util.Map$Entry r2 = (java.util.Map.Entry) r2
            java.lang.Object r3 = r2.getKey()
            java.lang.Integer r3 = (java.lang.Integer) r3
            int r3 = r3.intValue()
            r3 = r3 & r4
            if (r3 == 0) goto L4f
            java.lang.Object r2 = r2.getValue()
            com.google.android.gms.internal.mlkit_vision_barcode.D7 r2 = (com.google.android.gms.internal.mlkit_vision_barcode.D7) r2
            r0.f(r2)
            goto L4f
        L72:
            com.quizlet.data.repository.school.membership.a r4 = new com.quizlet.data.repository.school.membership.a
            r1 = 19
            r4.<init>(r1)
            com.google.android.gms.internal.mlkit_vision_barcode.B r0 = r0.h()
            r4.b = r0
            com.google.android.gms.internal.mlkit_vision_barcode.E7 r0 = new com.google.android.gms.internal.mlkit_vision_barcode.E7
            r0.<init>(r4)
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.mlkit.vision.barcode.internal.a.a(com.google.mlkit.vision.barcode.b):com.google.android.gms.internal.mlkit_vision_barcode.E7");
    }

    public static void b(J7 j7, EnumC3290w5 enumC3290w5) {
        j7.b(new com.quizlet.data.repository.school.membership.a(enumC3290w5, 25), EnumC3298x5.ON_DEVICE_BARCODE_LOAD);
    }

    public static boolean c() {
        AtomicReference atomicReference = c;
        if (atomicReference.get() != null) {
            return ((Boolean) atomicReference.get()).booleanValue();
        }
        Context contextB = com.google.mlkit.common.sdkinternal.f.c().b();
        B b2 = g.h;
        boolean z = com.google.android.gms.dynamite.c.a(contextB, "com.google.mlkit.dynamite.barcode") > 0;
        atomicReference.set(Boolean.valueOf(z));
        return z;
    }
}
