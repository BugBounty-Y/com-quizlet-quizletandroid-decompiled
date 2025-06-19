package kotlinx.coroutines;

import com.google.android.gms.internal.mlkit_vision_camera.G1;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class s0 extends y0 {
    public final kotlin.coroutines.h d;

    public s0(CoroutineContext coroutineContext, Function2 function2) {
        super(coroutineContext, true, false);
        this.d = kotlin.coroutines.intrinsics.h.a(this, this, function2);
    }

    @Override // kotlinx.coroutines.q0
    public final void c0() throws Throwable {
        G1.h(this.d, this);
    }
}
