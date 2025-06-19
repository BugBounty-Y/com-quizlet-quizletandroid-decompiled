package com.google.mlkit.vision.documentscanner.internal;

import android.os.SystemClock;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.i;
import com.google.android.gms.internal.mlkit_vision_barcode.C3268u;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3588c;
import com.google.android.gms.internal.mlkit_vision_document_scanner.EnumC3602d5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.EnumC3610e5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.H4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.I4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.J4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.p7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.r7;
import com.google.firebase.messaging.u;
import com.google.mlkit.common.sdkinternal.f;
import com.google.mlkit.common.sdkinternal.h;
import com.quizlet.data.interactor.folderwithcreator.m;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class b implements i {
    public static boolean f;
    public static int g;
    public final com.google.mlkit.vision.documentscanner.b a;
    public final Feature[] b;
    public final J4 c;
    public final p7 d;
    public final com.quizlet.data.repository.searchexplanations.c e;

    public b(com.google.mlkit.vision.documentscanner.b bVar) {
        p7 p7VarB = r7.b();
        com.quizlet.data.repository.searchexplanations.c cVar = new com.quizlet.data.repository.searchexplanations.c(f.c().b(), 9);
        this.a = bVar;
        G4 g4 = new G4();
        g4.c = H4.MODE_AUTO;
        Boolean bool = Boolean.TRUE;
        g4.d = bool;
        g4.e = bool;
        g4.b = Integer.valueOf(bVar.a);
        g4.k = Boolean.valueOf(bVar.c);
        g4.g = Boolean.valueOf(bVar.d);
        boolean z = bVar.e;
        g4.i = Boolean.valueOf(z);
        boolean z2 = bVar.f;
        g4.j = Boolean.valueOf(z2);
        Object[] objArrCopyOf = new Object[4];
        int[] iArr = bVar.b;
        int length = iArr.length;
        int i = 0;
        int i2 = 0;
        while (i < length) {
            int i3 = iArr[i];
            I4 i4 = i3 != 101 ? i3 != 102 ? I4.FORMAT_UNKNOWN : I4.FORMAT_PDF : I4.FORMAT_JPEG;
            int i5 = i2 + 1;
            int length2 = objArrCopyOf.length;
            if (length2 < i5) {
                int i6 = length2 + (length2 >> 1) + 1;
                if (i6 < i5) {
                    int iHighestOneBit = Integer.highestOneBit(i2);
                    i6 = iHighestOneBit + iHighestOneBit;
                }
                objArrCopyOf = Arrays.copyOf(objArrCopyOf, i6 < 0 ? SubsamplingScaleImageView.TILE_SIZE_AUTO : i6);
            }
            objArrCopyOf[i2] = i4;
            i++;
            i2 = i5;
        }
        g4.l = AbstractC3588c.h(i2, objArrCopyOf);
        g4.h = Boolean.FALSE;
        this.c = new J4(g4);
        this.e = cVar;
        this.d = p7VarB;
        C3268u c3268u = new C3268u(1);
        c3268u.e(h.c);
        if (z) {
            c3268u.e(h.e);
        }
        if (z2) {
            c3268u.e(h.d);
        }
        c3268u.c = true;
        this.b = (Feature[]) AbstractC3588c.h(c3268u.b, c3268u.a).toArray(new Feature[0]);
    }

    @Override // com.google.android.gms.common.api.i
    public final Feature[] a() {
        return this.b;
    }

    public final void b(EnumC3602d5 enumC3602d5, long j, long j2) {
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        long jCurrentTimeMillis = System.currentTimeMillis();
        m mVar = new m();
        u uVar = new u();
        uVar.a = Long.valueOf(Long.MAX_VALUE & (jElapsedRealtime - j));
        uVar.b = enumC3602d5;
        uVar.c = this.c;
        mVar.d = new L5(uVar);
        this.d.a(new com.quizlet.data.repository.widget.b(mVar), EnumC3610e5.ON_DEVICE_DOCUMENT_SCANNER_UI_FINISH);
        this.e.p(j2, jCurrentTimeMillis, enumC3602d5.a);
    }
}
