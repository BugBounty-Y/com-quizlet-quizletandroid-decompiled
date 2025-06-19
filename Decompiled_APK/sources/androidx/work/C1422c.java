package androidx.work;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3386r2;
import java.util.concurrent.ExecutorService;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.work.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1422c {
    public final ExecutorService a;
    public final kotlinx.coroutines.scheduling.e b;
    public final ExecutorService c;
    public final B d;
    public final T e;
    public final B f;
    public final androidx.camera.camera2.internal.compat.h g;
    public final int h;
    public final int i;
    public final int j;
    public final int k;
    public final boolean l;
    public final B m;

    public C1422c(G builder) {
        Intrinsics.checkNotNullParameter(builder, "builder");
        this.a = AbstractC3386r2.b(false);
        this.b = kotlinx.coroutines.O.a;
        this.c = AbstractC3386r2.b(true);
        this.d = new B();
        T t = (androidx.hilt.work.a) builder.a;
        this.e = t == null ? C1439m.a : t;
        this.f = B.a;
        this.g = new androidx.camera.camera2.internal.compat.h();
        this.h = 4;
        this.i = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        this.k = 20;
        this.j = 8;
        this.l = true;
        this.m = new B();
    }
}
