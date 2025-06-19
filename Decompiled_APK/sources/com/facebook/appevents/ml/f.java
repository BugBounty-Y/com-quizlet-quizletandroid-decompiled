package com.facebook.appevents.ml;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Matrix;
import android.graphics.drawable.Drawable;
import android.hardware.camera2.CameraCharacteristics;
import android.net.Uri;
import android.widget.ImageView;
import androidx.camera.camera2.internal.compat.q;
import androidx.compose.runtime.C0804k;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.runtime.V;
import androidx.compose.ui.n;
import com.bumptech.glide.k;
import com.bumptech.glide.load.resource.bitmap.t;
import com.facebook.appevents.ml.f;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3223o5;
import com.google.android.gms.internal.mlkit_vision_barcode.L4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R4;
import com.quizlet.features.achievements.ui.composables.p;
import com.quizlet.features.achievements.ui.composables.s;
import com.quizlet.themes.m;
import com.quizlet.ui.resources.designsystem.generated.j;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class f {
    public static final void a(kotlinx.collections.immutable.b sets, kotlinx.collections.immutable.b rounds, kotlinx.collections.immutable.b solutions, n nVar, Function1 function1, InterfaceC0806l interfaceC0806l, int i) {
        int i2;
        n nVar2;
        Intrinsics.checkNotNullParameter(sets, "sets");
        Intrinsics.checkNotNullParameter(rounds, "rounds");
        Intrinsics.checkNotNullParameter(solutions, "solutions");
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-7553802);
        if ((i & 6) == 0) {
            i2 = (c0814p.h(sets) ? 4 : 2) | i;
        } else {
            i2 = i;
        }
        if ((i & 48) == 0) {
            i2 |= c0814p.h(rounds) ? 32 : 16;
        }
        if ((i & 384) == 0) {
            i2 |= c0814p.h(solutions) ? 256 : 128;
        }
        int i3 = i2 | 3072;
        if ((i & 24576) == 0) {
            i3 |= c0814p.h(function1) ? 16384 : 8192;
        }
        int i4 = i3;
        if ((i4 & 9363) == 9362 && c0814p.x()) {
            c0814p.Q();
            nVar2 = nVar;
        } else {
            nVar2 = n.b;
            V v = C0804k.a;
            Object[] objArr = new Object[0];
            c0814p.X(1485259530);
            Object objI = c0814p.I();
            if (objI == v) {
                objI = new com.quizlet.db.data.models.persisted.types.a(21);
                c0814p.i0(objI);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a0 = (InterfaceC0773a0) L4.d(objArr, null, (Function0) objI, c0814p, 3072, 6);
            Object[] objArr2 = new Object[0];
            c0814p.X(1485261738);
            Object objI2 = c0814p.I();
            if (objI2 == v) {
                objI2 = new com.quizlet.db.data.models.persisted.types.a(22);
                c0814p.i0(objI2);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a02 = (InterfaceC0773a0) L4.d(objArr2, null, (Function0) objI2, c0814p, 3072, 6);
            Object[] objArr3 = new Object[0];
            c0814p.X(1485264042);
            Object objI3 = c0814p.I();
            if (objI3 == v) {
                objI3 = new com.quizlet.db.data.models.persisted.types.a(23);
                c0814p.i0(objI3);
            }
            c0814p.p(false);
            InterfaceC0773a0 interfaceC0773a03 = (InterfaceC0773a0) L4.d(objArr3, null, (Function0) objI3, c0814p, 3072, 6);
            androidx.compose.material3.windowsizeclass.b bVarG = AbstractC3205m5.g(c0814p);
            Set set = androidx.compose.material3.windowsizeclass.c.b;
            int i5 = bVarG.a == 2 ? 5 : 2;
            int size = AbstractC3205m5.g(c0814p).a == 2 ? 5 : 4;
            float fA = AbstractC3223o5.a(c0814p, i5);
            m.g.t();
            float f = fA - j.k;
            int size2 = ((Boolean) interfaceC0773a0.getValue()).booleanValue() ? sets.size() : size;
            int size3 = ((Boolean) interfaceC0773a02.getValue()).booleanValue() ? rounds.size() : size;
            if (((Boolean) interfaceC0773a03.getValue()).booleanValue()) {
                size = solutions.size();
            }
            R4.a(nVar2, null, 0L, 0L, 0L, null, false, null, null, null, androidx.compose.runtime.internal.e.e(-1694483204, new s(f, i5, size2, size3, size, interfaceC0773a0, interfaceC0773a02, interfaceC0773a03, function1, sets, rounds, solutions), c0814p), c0814p, (i4 >> 9) & 14, 1022);
            c0814p = c0814p;
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new p(sets, rounds, solutions, nVar2, function1, i, 0);
        }
    }

    public static final void b(a x, a b) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(x, "x");
            Intrinsics.checkNotNullParameter(b, "b");
            int[] iArr = x.a;
            int i = iArr[0];
            int i2 = iArr[1];
            int i3 = iArr[2];
            float[] fArr = x.c;
            float[] fArr2 = b.c;
            for (int i4 = 0; i4 < i; i4++) {
                for (int i5 = 0; i5 < i2; i5++) {
                    for (int i6 = 0; i6 < i3; i6++) {
                        int i7 = (i5 * i3) + (i4 * i2 * i3) + i6;
                        fArr[i7] = fArr[i7] + fArr2[i6];
                    }
                }
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
        }
    }

    public static final a c(a[] tensors) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(tensors, "tensors");
            int i = tensors[0].a[0];
            int i2 = 0;
            for (a aVar : tensors) {
                i2 += aVar.a[1];
            }
            a aVar2 = new a(new int[]{i, i2});
            float[] fArr = aVar2.c;
            for (int i3 = 0; i3 < i; i3++) {
                int i4 = i3 * i2;
                for (a aVar3 : tensors) {
                    float[] fArr2 = aVar3.c;
                    int i5 = aVar3.a[1];
                    System.arraycopy(fArr2, i3 * i5, fArr, i4, i5);
                    i4 += i5;
                }
            }
            return aVar2;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
            return null;
        }
    }

    public static final a d(a x, a w) {
        a aVar;
        a aVar2 = null;
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(x, "x");
            Intrinsics.checkNotNullParameter(w, "w");
            int[] iArr = x.a;
            int i = 0;
            int i2 = iArr[0];
            int i3 = iArr[1];
            int i4 = iArr[2];
            int[] iArr2 = w.a;
            int i5 = iArr2[0];
            int i6 = (i3 - i5) + 1;
            int i7 = iArr2[2];
            a aVar3 = new a(new int[]{i2, i6, i7});
            float[] fArr = x.c;
            float[] fArr2 = aVar3.c;
            float[] fArr3 = w.c;
            int i8 = 0;
            while (i8 < i2) {
                int i9 = i;
                while (i9 < i7) {
                    int i10 = i;
                    while (i10 < i6) {
                        float f = DefinitionKt.NO_Float_VALUE;
                        aVar = aVar2;
                        int i11 = i;
                        while (i11 < i5) {
                            while (i < i4) {
                                try {
                                    f = (fArr[((i11 + i10) * i4) + (i3 * i4 * i8) + i] * fArr3[(((i11 * i4) + i) * i7) + i9]) + f;
                                    i++;
                                } catch (Throwable th) {
                                    th = th;
                                    com.facebook.internal.instrument.crashshield.a.a(f.class, th);
                                    return aVar;
                                }
                            }
                            i11++;
                            i = 0;
                        }
                        fArr2[(i10 * i7) + (i6 * i7 * i8) + i9] = f;
                        i10++;
                        aVar2 = aVar;
                        i = 0;
                    }
                    i9++;
                    i = 0;
                }
                i8++;
                i = 0;
            }
            return aVar3;
        } catch (Throwable th2) {
            th = th2;
            aVar = null;
        }
    }

    public static String e(q qVar, Integer num, List list) {
        if (num != null && list.contains("0") && list.contains("1")) {
            if (num.intValue() == 1) {
                if (((Integer) qVar.b("0").a(CameraCharacteristics.LENS_FACING)).intValue() == 1) {
                    return "1";
                }
            } else if (num.intValue() == 0 && ((Integer) qVar.b("1").a(CameraCharacteristics.LENS_FACING)).intValue() == 0) {
                return "0";
            }
        }
        return null;
    }

    public static final a f(a x, a w, a b) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(x, "x");
            Intrinsics.checkNotNullParameter(w, "w");
            Intrinsics.checkNotNullParameter(b, "b");
            int i = x.a[0];
            int i2 = b.a[0];
            a aVarL = l(x, w);
            float[] fArr = b.c;
            float[] fArr2 = aVarL.c;
            for (int i3 = 0; i3 < i; i3++) {
                for (int i4 = 0; i4 < i2; i4++) {
                    int i5 = (i3 * i2) + i4;
                    fArr2[i5] = fArr2[i5] + fArr[i4];
                }
            }
            return aVarL;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
            return null;
        }
    }

    public static final a g(String[] texts, a w) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(texts, "texts");
            Intrinsics.checkNotNullParameter(w, "w");
            int length = texts.length;
            int i = w.a[1];
            a aVar = new a(new int[]{length, 128, i});
            float[] fArr = aVar.c;
            float[] fArr2 = w.c;
            for (int i2 = 0; i2 < length; i2++) {
                int[] iArrD = g.a.d(texts[i2]);
                for (int i3 = 0; i3 < 128; i3++) {
                    System.arraycopy(fArr2, iArrD[i3] * i, fArr, (i * i3) + (i * 128 * i2), i);
                }
            }
            return aVar;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
            return null;
        }
    }

    public static final void h(a x) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(x, "x");
            int[] iArr = x.a;
            if (1 >= iArr.length) {
                return;
            }
            int length = iArr.length;
            int i = 1;
            for (int i2 = 1; i2 < length; i2++) {
                i *= x.a[i2];
            }
            int[] shape = {x.a[0], i};
            Intrinsics.checkNotNullParameter(shape, "shape");
            x.a = shape;
            int iA = g.a(shape);
            float[] fArr = new float[iA];
            System.arraycopy(x.c, 0, fArr, 0, Math.min(x.b, iA));
            x.c = fArr;
            x.b = iA;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
        }
    }

    public static Bitmap i(File file) {
        String absolutePath = file.getAbsolutePath();
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inJustDecodeBounds = true;
        BitmapFactory.decodeFile(absolutePath, options);
        int iMin = Math.min(options.outWidth / 1024, options.outHeight / 1024);
        options.inJustDecodeBounds = false;
        options.inSampleSize = iMin;
        return BitmapFactory.decodeFile(absolutePath, options);
    }

    public static void j(final int i, final int i2, final Uri uri, final ImageView imageView, com.quizlet.qutils.image.loading.a aVar) {
        final com.quizlet.quizletandroid.ui.common.images.loading.glide.a aVar2 = (com.quizlet.quizletandroid.ui.common.images.loading.glide.a) aVar;
        com.onetrust.otpublishers.headless.UI.fragment.q qVarA = aVar2.a(imageView.getContext());
        Intrinsics.checkNotNullParameter(uri, "uri");
        com.quizlet.qutils.data.offline.c ttl = com.quizlet.qutils.data.offline.c.b;
        Intrinsics.checkNotNullParameter(uri, "uri");
        Intrinsics.checkNotNullParameter(ttl, "ttl");
        String string = uri.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        com.quizlet.quizletandroid.ui.common.images.loading.offline.a aVar3 = new com.quizlet.quizletandroid.ui.common.images.loading.offline.a(string);
        com.bumptech.glide.m mVar = (com.bumptech.glide.m) qVarA.b;
        mVar.getClass();
        final com.quizlet.data.repository.widget.b bVar = new com.quizlet.data.repository.widget.b(new k(mVar.a, mVar, Drawable.class, mVar.b).D(aVar3));
        if (i > 0) {
            com.bumptech.glide.request.f fVar = (com.bumptech.glide.request.f) bVar.c;
            fVar.i(i, i);
            timber.log.c.a.o("`onlyScaleDown` is no-op for GlideImageRequest", new Object[0]);
            fVar.m(com.bumptech.glide.load.resource.bitmap.m.b, new t(), true);
        }
        imageView.post(new Runnable() { // from class: com.quizlet.qutils.image.a
            @Override // java.lang.Runnable
            public final void run() {
                final ImageView imageView2 = imageView;
                final Uri uri2 = uri;
                final int i3 = i2;
                final int i4 = i;
                final com.quizlet.qutils.image.loading.a aVar4 = aVar2;
                bVar.p(imageView2, null, new com.quizlet.qutils.rx.b() { // from class: com.quizlet.qutils.image.b
                    @Override // com.quizlet.qutils.rx.b
                    public final void run() {
                        int i5 = i3;
                        if (i5 > 0) {
                            int i6 = i4;
                            f.j(i6 == 0 ? 1024 : i6 / 2, i5 - 1, uri2, imageView2, aVar4);
                        }
                    }
                });
            }
        });
    }

    public static final a k(a x, int i) {
        a aVar;
        a aVar2 = null;
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(x, "x");
            int[] iArr = x.a;
            int i2 = 0;
            int i3 = iArr[0];
            int i4 = iArr[1];
            int i5 = iArr[2];
            int i6 = (i4 - i) + 1;
            a aVar3 = new a(new int[]{i3, i6, i5});
            float[] fArr = x.c;
            float[] fArr2 = aVar3.c;
            int i7 = 0;
            while (i7 < i3) {
                int i8 = i2;
                while (i8 < i5) {
                    int i9 = i2;
                    while (i9 < i6) {
                        int i10 = i9 * i5;
                        int i11 = (i7 * i6 * i5) + i10 + i8;
                        int i12 = (i7 * i4 * i5) + i10 + i8;
                        fArr2[i11] = Float.MIN_VALUE;
                        int i13 = i2;
                        while (i13 < i) {
                            aVar = aVar2;
                            try {
                                fArr2[i11] = Math.max(fArr2[i11], fArr[(i13 * i5) + i12]);
                                i13++;
                                aVar2 = aVar;
                            } catch (Throwable th) {
                                th = th;
                                com.facebook.internal.instrument.crashshield.a.a(f.class, th);
                                return aVar;
                            }
                        }
                        i9++;
                        i2 = 0;
                    }
                    i8++;
                    i2 = 0;
                }
                i7++;
                i2 = 0;
            }
            return aVar3;
        } catch (Throwable th2) {
            th = th2;
            aVar = aVar2;
        }
    }

    public static final a l(a x, a w) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(x, "x");
            Intrinsics.checkNotNullParameter(w, "w");
            int i = x.a[0];
            int[] iArr = w.a;
            int i2 = iArr[0];
            int i3 = iArr[1];
            a aVar = new a(new int[]{i, i3});
            float[] fArr = x.c;
            float[] fArr2 = w.c;
            float[] fArr3 = aVar.c;
            for (int i4 = 0; i4 < i; i4++) {
                for (int i5 = 0; i5 < i3; i5++) {
                    int i6 = (i4 * i3) + i5;
                    fArr3[i6] = 0.0f;
                    for (int i7 = 0; i7 < i2; i7++) {
                        fArr3[i6] = (fArr[(i4 * i2) + i7] * fArr2[(i7 * i3) + i5]) + fArr3[i6];
                    }
                }
            }
            return aVar;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
            return null;
        }
    }

    public static final void m(a x) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(x, "x");
            float[] fArr = x.c;
            int length = fArr.length;
            for (int i = 0; i < length; i++) {
                if (fArr[i] < DefinitionKt.NO_Float_VALUE) {
                    fArr[i] = 0.0f;
                }
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0019 A[PHI: r2
  0x0019: PHI (r2v4 android.graphics.Bitmap) = (r2v3 android.graphics.Bitmap), (r2v5 android.graphics.Bitmap) binds: [B:29:0x005e, B:6:0x0017] A[DONT_GENERATE, DONT_INLINE]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean n(java.io.File r5) {
        /*
            r0 = 0
            r1 = 0
            android.graphics.Bitmap r2 = i(r5)     // Catch: java.lang.Throwable -> L51 java.io.IOException -> L54
            if (r2 != 0) goto L2b
            java.lang.String r3 = "ImageUtil couldn't resize/decode image file: %s"
            java.lang.String r5 = r5.getName()     // Catch: java.lang.Throwable -> L27 java.io.IOException -> L29
            java.lang.Object[] r5 = new java.lang.Object[]{r5}     // Catch: java.lang.Throwable -> L27 java.io.IOException -> L29
            timber.log.a r4 = timber.log.c.a     // Catch: java.lang.Throwable -> L27 java.io.IOException -> L29
            r4.d(r3, r5)     // Catch: java.lang.Throwable -> L27 java.io.IOException -> L29
            if (r2 == 0) goto L1c
        L19:
            r2.recycle()
        L1c:
            java.lang.System.gc()
            java.lang.Runtime r5 = java.lang.Runtime.getRuntime()
            r5.gc()
            return r0
        L27:
            r5 = move-exception
            goto L61
        L29:
            r5 = move-exception
            goto L56
        L2b:
            java.io.FileOutputStream r3 = new java.io.FileOutputStream     // Catch: java.lang.Throwable -> L27 java.io.IOException -> L29
            r3.<init>(r5)     // Catch: java.lang.Throwable -> L27 java.io.IOException -> L29
            android.graphics.Bitmap$CompressFormat r5 = com.quizlet.qutils.image.capture.c.a(r5)     // Catch: java.lang.Throwable -> L4b java.io.IOException -> L4e
            r1 = 92
            boolean r5 = r2.compress(r5, r1, r3)     // Catch: java.lang.Throwable -> L4b java.io.IOException -> L4e
            okhttp3.internal.b.d(r3)
            r2.recycle()
            java.lang.System.gc()
            java.lang.Runtime r0 = java.lang.Runtime.getRuntime()
            r0.gc()
            return r5
        L4b:
            r5 = move-exception
            r1 = r3
            goto L61
        L4e:
            r5 = move-exception
            r1 = r3
            goto L56
        L51:
            r5 = move-exception
            r2 = r1
            goto L61
        L54:
            r5 = move-exception
            r2 = r1
        L56:
            timber.log.c.a(r5)     // Catch: java.lang.Throwable -> L27
            if (r1 == 0) goto L5e
            okhttp3.internal.b.d(r1)
        L5e:
            if (r2 == 0) goto L1c
            goto L19
        L61:
            if (r1 == 0) goto L66
            okhttp3.internal.b.d(r1)
        L66:
            if (r2 == 0) goto L6b
            r2.recycle()
        L6b:
            java.lang.System.gc()
            java.lang.Runtime r0 = java.lang.Runtime.getRuntime()
            r0.gc()
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.ml.f.n(java.io.File):boolean");
    }

    public static void o(int i, String str) throws IOException {
        if (i <= 0) {
            return;
        }
        try {
            Bitmap bitmapDecodeFile = BitmapFactory.decodeFile(str);
            Matrix matrix = new Matrix();
            matrix.setRotate(i);
            Bitmap bitmapCreateBitmap = Bitmap.createBitmap(bitmapDecodeFile, 0, 0, bitmapDecodeFile.getWidth(), bitmapDecodeFile.getHeight(), matrix, true);
            File file = new File(str);
            FileOutputStream fileOutputStream = new FileOutputStream(str);
            bitmapCreateBitmap.compress(com.quizlet.qutils.image.capture.c.a(file), 100, fileOutputStream);
            fileOutputStream.flush();
            fileOutputStream.close();
            bitmapCreateBitmap.recycle();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static final void p(a x) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(x, "x");
            int[] iArr = x.a;
            int i = iArr[0];
            int i2 = iArr[1];
            float[] fArr = x.c;
            for (int i3 = 0; i3 < i; i3++) {
                int i4 = i3 * i2;
                int i5 = i4 + i2;
                float f = Float.MIN_VALUE;
                for (int i6 = i4; i6 < i5; i6++) {
                    float f2 = fArr[i6];
                    if (f2 > f) {
                        f = f2;
                    }
                }
                float f3 = DefinitionKt.NO_Float_VALUE;
                for (int i7 = i4; i7 < i5; i7++) {
                    float fExp = (float) Math.exp(fArr[i7] - f);
                    fArr[i7] = fExp;
                    f3 += fExp;
                }
                while (i4 < i5) {
                    fArr[i4] = fArr[i4] / f3;
                    i4++;
                }
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
        }
    }

    public static final a q(a x) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(x, "x");
            int[] iArr = x.a;
            int i = iArr[0];
            int i2 = iArr[1];
            a aVar = new a(new int[]{i2, i});
            float[] fArr = x.c;
            float[] fArr2 = aVar.c;
            for (int i3 = 0; i3 < i; i3++) {
                for (int i4 = 0; i4 < i2; i4++) {
                    fArr2[(i4 * i) + i3] = fArr[(i3 * i2) + i4];
                }
            }
            return aVar;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
            return null;
        }
    }

    public static final a r(a x) {
        if (com.facebook.internal.instrument.crashshield.a.b(f.class)) {
            return null;
        }
        try {
            Intrinsics.checkNotNullParameter(x, "x");
            int[] iArr = x.a;
            int i = iArr[0];
            int i2 = iArr[1];
            int i3 = iArr[2];
            a aVar = new a(new int[]{i3, i2, i});
            float[] fArr = x.c;
            float[] fArr2 = aVar.c;
            for (int i4 = 0; i4 < i; i4++) {
                for (int i5 = 0; i5 < i2; i5++) {
                    for (int i6 = 0; i6 < i3; i6++) {
                        fArr2[(i5 * i) + (i6 * i * i2) + i4] = fArr[(i5 * i3) + (i4 * i2 * i3) + i6];
                    }
                }
            }
            return aVar;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(f.class, th);
            return null;
        }
    }
}
