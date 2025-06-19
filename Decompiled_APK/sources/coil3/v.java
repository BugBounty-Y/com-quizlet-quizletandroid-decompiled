package coil3;

import android.content.Context;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class v {
    public static final /* synthetic */ AtomicReference a = new AtomicReference(null);

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v11, types: [coil3.m] */
    public static final m a(Context context) {
        u uVar;
        AtomicReference atomicReference = a;
        Object obj = atomicReference.get();
        u uVarA = null;
        m mVar = obj instanceof m ? (m) obj : null;
        if (mVar != null) {
            return mVar;
        }
        while (true) {
            Object obj2 = atomicReference.get();
            if (obj2 instanceof m) {
                uVar = uVarA;
                uVarA = (m) obj2;
            } else {
                if (uVarA == null) {
                    if (obj2 instanceof w) {
                    }
                    context.getApplicationContext();
                    androidx.compose.runtime.external.kotlinx.collections.immutable.implementations.immutableList.e eVar = x.a;
                    uVarA = w.a(context);
                }
                uVar = uVarA;
            }
            while (!atomicReference.compareAndSet(obj2, uVarA)) {
                if (atomicReference.get() != obj2) {
                    break;
                }
            }
            Intrinsics.e(uVarA, "null cannot be cast to non-null type coil3.ImageLoader");
            return uVarA;
            uVarA = uVar;
        }
    }
}
