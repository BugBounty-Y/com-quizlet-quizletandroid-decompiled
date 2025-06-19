package androidx.appcompat.view.menu;

import android.content.res.Resources;
import android.os.Bundle;
import android.os.RemoteException;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.c0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3215n6;
import com.google.android.gms.internal.mlkit_vision_barcode.C3198l7;
import com.google.android.gms.internal.mlkit_vision_barcode.C3268u;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3298x5;
import com.google.android.gms.internal.mlkit_vision_barcode.J7;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3588c;
import com.google.android.gms.internal.mlkit_vision_document_scanner.C3604e;
import com.google.android.gms.internal.mlkit_vision_document_scanner.EnumC3610e5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.R6;
import com.google.android.gms.internal.mlkit_vision_document_scanner.p7;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.InterfaceC3897v;
import com.google.android.gms.measurement.internal.R0;
import com.google.android.gms.measurement.internal.S0;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.Y0;
import com.google.android.gms.measurement.internal.zzpc;
import com.google.android.gms.measurement.internal.zzr;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: androidx.appcompat.view.menu.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class RunnableC0069f implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    public /* synthetic */ RunnableC0069f(int i, Object obj, Object obj2, Object obj3, Object obj4, boolean z) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
    }

    private final void a() {
        String str;
        com.google.android.gms.internal.mlkit_vision_barcode.B bH;
        J7 j7 = (J7) this.b;
        C0122z c0122z = (C0122z) this.c;
        EnumC3298x5 enumC3298x5 = (EnumC3298x5) this.d;
        String str2 = (String) this.e;
        j7.getClass();
        c0 c0Var = (c0) c0122z.c;
        c0Var.c = enumC3298x5;
        C3198l7 c3198l7 = (C3198l7) c0Var.b;
        if (c3198l7 == null || (str = c3198l7.d) == null || str.isEmpty()) {
            str = "NA";
        } else {
            com.google.android.gms.common.internal.u.h(str);
        }
        C3 c3 = new C3();
        c3.a = j7.a;
        c3.b = j7.b;
        synchronized (J7.class) {
            try {
                bH = J7.k;
                if (bH == null) {
                    androidx.core.os.f fVarI = AbstractC3215n6.i(Resources.getSystem().getConfiguration());
                    C3268u c3268u = new C3268u(0);
                    for (int i = 0; i < fVarI.c(); i++) {
                        Locale localeB = fVarI.b(i);
                        com.quizlet.data.repository.widget.b bVar = com.google.mlkit.common.sdkinternal.c.a;
                        c3268u.f(localeB.toLanguageTag());
                    }
                    bH = c3268u.h();
                    J7.k = bH;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        c3.e = bH;
        c3.h = Boolean.TRUE;
        c3.d = str;
        c3.c = str2;
        c3.f = j7.f.l() ? (String) j7.f.h() : j7.d.a();
        c3.j = 10;
        c3.k = Integer.valueOf(j7.h);
        c0122z.d = c3;
        j7.c.a(c0122z);
    }

    private final void b() {
        String str;
        C3604e c3604eH;
        p7 p7Var = (p7) this.b;
        com.quizlet.data.repository.widget.b bVar = (com.quizlet.data.repository.widget.b) this.c;
        EnumC3610e5 enumC3610e5 = (EnumC3610e5) this.d;
        String str2 = (String) this.e;
        p7Var.getClass();
        com.quizlet.data.interactor.folderwithcreator.m mVar = (com.quizlet.data.interactor.folderwithcreator.m) bVar.b;
        mVar.b = enumC3610e5;
        R6 r6 = (R6) mVar.a;
        if (r6 == null || (str = r6.d) == null || str.isEmpty()) {
            str = "NA";
        }
        C3 c3 = new C3();
        c3.a = p7Var.a;
        c3.b = p7Var.b;
        synchronized (p7.class) {
            try {
                c3604eH = p7.i;
                if (c3604eH == null) {
                    androidx.core.os.f fVarI = AbstractC3215n6.i(Resources.getSystem().getConfiguration());
                    Object[] objArrCopyOf = new Object[4];
                    int i = 0;
                    int i2 = 0;
                    while (i < fVarI.c()) {
                        Locale localeB = fVarI.b(i);
                        com.quizlet.data.repository.widget.b bVar2 = com.google.mlkit.common.sdkinternal.c.a;
                        String languageTag = localeB.toLanguageTag();
                        languageTag.getClass();
                        int i3 = i2 + 1;
                        int length = objArrCopyOf.length;
                        if (length < i3) {
                            int i4 = length + (length >> 1) + 1;
                            if (i4 < i3) {
                                int iHighestOneBit = Integer.highestOneBit(i2);
                                i4 = iHighestOneBit + iHighestOneBit;
                            }
                            if (i4 < 0) {
                                i4 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
                            }
                            objArrCopyOf = Arrays.copyOf(objArrCopyOf, i4);
                        }
                        objArrCopyOf[i2] = languageTag;
                        i++;
                        i2 = i3;
                    }
                    c3604eH = AbstractC3588c.h(i2, objArrCopyOf);
                    p7.i = c3604eH;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        c3.e = c3604eH;
        c3.h = Boolean.TRUE;
        c3.d = str;
        c3.c = str2;
        c3.f = p7Var.f.l() ? (String) p7Var.f.h() : p7Var.d.a();
        c3.j = 10;
        c3.k = Integer.valueOf(p7Var.h);
        bVar.c = c3;
        p7Var.c.a(bVar);
    }

    private final void c() {
        InterfaceC3897v interfaceC3897v;
        Y0 y0 = (Y0) this.b;
        AtomicReference atomicReference = (AtomicReference) this.c;
        zzr zzrVar = (zzr) this.d;
        Bundle bundle = (Bundle) this.e;
        synchronized (atomicReference) {
            try {
                interfaceC3897v = y0.e;
            } catch (RemoteException e) {
                I i = ((Y) y0.b).i;
                Y.k(i);
                i.g.g("Failed to request trigger URIs; remote exception", e);
                atomicReference.notifyAll();
            }
            if (interfaceC3897v != null) {
                interfaceC3897v.g2(zzrVar, bundle, new R0(atomicReference));
                y0.h0();
            } else {
                I i2 = ((Y) y0.b).i;
                Y.k(i2);
                i2.g.f("Failed to request trigger URIs; not connected to service");
            }
        }
    }

    private final void d() {
        InterfaceC3897v interfaceC3897v;
        Y0 y0 = (Y0) this.b;
        AtomicReference atomicReference = (AtomicReference) this.c;
        zzr zzrVar = (zzr) this.d;
        zzpc zzpcVar = (zzpc) this.e;
        synchronized (atomicReference) {
            try {
                interfaceC3897v = y0.e;
            } catch (RemoteException e) {
                I i = ((Y) y0.b).i;
                Y.k(i);
                i.g.g("[sgtm] Failed to get upload batches; remote exception", e);
                atomicReference.notifyAll();
            }
            if (interfaceC3897v != null) {
                interfaceC3897v.M2(zzrVar, zzpcVar, new S0(y0, atomicReference));
                y0.h0();
            } else {
                I i2 = ((Y) y0.b).i;
                Y.k(i2);
                i2.g.f("[sgtm] Failed to get upload batches; not connected to service");
            }
        }
    }

    /* JADX WARN: Can't wrap try/catch for region: R(16:270|75|(1:77)(5:78|(2:81|(1:99))|100|97|273)|83|(2:86|84)|275|87|246|88|(2:91|89)|276|93|(1:95)|96|97|273) */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x03f9, code lost:
    
        r6 = r16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x0430, code lost:
    
        r2.c().j.g("Failed to parse queued batch. appId", r4);
     */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() throws java.io.IOException, android.database.SQLException {
        /*
            Method dump skipped, instructions count: 1906
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.view.menu.RunnableC0069f.run():void");
    }

    public /* synthetic */ RunnableC0069f(Object obj, Object obj2, Object obj3, Object obj4, int i) {
        this.a = i;
        this.e = obj;
        this.b = obj2;
        this.c = obj3;
        this.d = obj4;
    }
}
