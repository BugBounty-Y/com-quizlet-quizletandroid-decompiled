package kotlin.sequences;

import androidx.collection.L;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.collections.F;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g implements Sequence {
    public final /* synthetic */ int a = 0;
    public final Object b;
    public final Object c;

    /* JADX WARN: Multi-variable type inference failed */
    public g(Function0 getInitialValue, Function1 getNextValue) {
        Intrinsics.checkNotNullParameter(getInitialValue, "getInitialValue");
        Intrinsics.checkNotNullParameter(getNextValue, "getNextValue");
        this.b = (kotlin.jvm.internal.r) getInitialValue;
        this.c = getNextValue;
    }

    @Override // kotlin.sequences.Sequence
    public final Iterator iterator() {
        switch (this.a) {
            case 0:
                return new L(this);
            default:
                ArrayList arrayListK = q.k((f) this.b);
                F.t(arrayListK, (androidx.camera.core.impl.utils.a) this.c);
                return arrayListK.iterator();
        }
    }

    public g(f fVar, androidx.camera.core.impl.utils.a aVar) {
        this.b = fVar;
        this.c = aVar;
    }
}
