package kotlinx.coroutines.channels;

import com.google.android.gms.internal.mlkit_vision_camera.F1;
import kotlin.jvm.functions.Function0;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.c {
    public Function0 j;
    public /* synthetic */ Object k;
    public int l;

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        this.k = obj;
        this.l |= Integer.MIN_VALUE;
        return F1.a(null, null, this);
    }
}
