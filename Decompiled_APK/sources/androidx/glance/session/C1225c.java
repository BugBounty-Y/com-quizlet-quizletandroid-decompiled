package androidx.glance.session;

import androidx.camera.camera2.internal.C0132i;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3348i;
import java.util.concurrent.atomic.AtomicBoolean;

/* renamed from: androidx.glance.session.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1225c extends kotlin.coroutines.jvm.internal.c {
    public AtomicBoolean j;
    public C0132i k;
    public kotlinx.coroutines.channels.w l;
    public kotlinx.coroutines.channels.c m;
    public /* synthetic */ Object n;
    public int o;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.n = obj;
        this.o |= Integer.MIN_VALUE;
        return AbstractC3348i.f(this);
    }
}
