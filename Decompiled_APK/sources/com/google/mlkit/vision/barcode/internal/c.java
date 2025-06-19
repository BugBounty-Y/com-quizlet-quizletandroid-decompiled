package com.google.mlkit.vision.barcode.internal;

import androidx.appcompat.view.menu.RunnableC0069f;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.c0;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.common.Feature;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3282v5;
import com.google.android.gms.internal.mlkit_vision_barcode.EnumC3298x5;
import com.google.android.gms.internal.mlkit_vision_barcode.I5;
import com.google.android.gms.internal.mlkit_vision_barcode.J7;
import com.google.mlkit.common.sdkinternal.h;
import com.google.mlkit.common.sdkinternal.k;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class c extends com.google.mlkit.vision.common.internal.b implements com.google.mlkit.vision.barcode.a {
    public final boolean f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(com.google.mlkit.vision.barcode.b bVar, e eVar, Executor executor, J7 j7) {
        super(eVar, executor);
        bVar.getClass();
        boolean zC = a.c();
        this.f = zC;
        C1608n c1608n = new C1608n();
        c1608n.b = a.a(bVar);
        I5 i5 = new I5(c1608n);
        c0 c0Var = new c0(9, false);
        c0Var.d = zC ? EnumC3282v5.TYPE_THICK : EnumC3282v5.TYPE_THIN;
        c0Var.e = i5;
        k.a.execute(new RunnableC0069f(12, j7, new C0122z(c0Var, 1), EnumC3298x5.ON_DEVICE_BARCODE_CREATE, j7.c(), false));
    }

    @Override // com.google.android.gms.common.api.i
    public final Feature[] a() {
        return this.f ? h.a : new Feature[]{h.b};
    }

    @Override // com.google.mlkit.vision.common.internal.b, java.io.Closeable, java.lang.AutoCloseable, com.google.mlkit.vision.barcode.a
    public final synchronized void close() {
        super.close();
    }
}
