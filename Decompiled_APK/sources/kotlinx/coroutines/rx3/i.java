package kotlinx.coroutines.rx3;

import com.google.android.gms.internal.mlkit_vision_camera.J1;
import kotlin.C4937f;
import kotlin.coroutines.CoroutineContext;
import kotlinx.coroutines.AbstractC4972a;

/* loaded from: classes3.dex */
public final class i extends AbstractC4972a {
    public final io.reactivex.rxjava3.internal.operators.single.c d;

    public i(CoroutineContext coroutineContext, io.reactivex.rxjava3.internal.operators.single.c cVar) {
        super(coroutineContext, false, true);
        this.d = cVar;
    }

    @Override // kotlinx.coroutines.AbstractC4972a
    public final void k0(Throwable th, boolean z) {
        try {
            if (this.d.b(th)) {
                return;
            }
        } catch (Throwable th2) {
            C4937f.a(th, th2);
        }
        J1.a(this.c, th);
    }

    @Override // kotlinx.coroutines.AbstractC4972a
    public final void l0(Object obj) {
        try {
            this.d.onSuccess(obj);
        } catch (Throwable th) {
            J1.a(this.c, th);
        }
    }
}
