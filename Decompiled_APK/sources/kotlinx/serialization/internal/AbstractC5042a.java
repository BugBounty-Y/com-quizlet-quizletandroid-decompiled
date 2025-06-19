package kotlinx.serialization.internal;

import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.encoding.Decoder;

/* renamed from: kotlinx.serialization.internal.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public abstract class AbstractC5042a implements KSerializer {
    public abstract Object a();

    public abstract int b(Object obj);

    public abstract Iterator c(Object obj);

    public abstract int d(Object obj);

    @Override // kotlinx.serialization.KSerializer
    public Object deserialize(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        return e(decoder);
    }

    public final Object e(Decoder decoder) {
        Intrinsics.checkNotNullParameter(decoder, "decoder");
        Object objA = a();
        int iB = b(objA);
        kotlinx.serialization.encoding.a aVarC = decoder.c(getDescriptor());
        while (true) {
            int iT = aVarC.t(getDescriptor());
            if (iT == -1) {
                aVarC.b(getDescriptor());
                return h(objA);
            }
            f(aVarC, iT + iB, objA);
        }
    }

    public abstract void f(kotlinx.serialization.encoding.a aVar, int i, Object obj);

    public abstract Object g(Object obj);

    public abstract Object h(Object obj);
}
