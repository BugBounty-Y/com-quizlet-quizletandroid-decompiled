package androidx.compose.foundation.gestures;

import androidx.compose.material3.U4;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class n1 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ float b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ n1(float f, Object obj, Object obj2, int i) {
        super(1);
        this.a = i;
        this.b = f;
        this.c = obj;
        this.d = obj2;
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0081 A[PHI: r1
  0x0081: PHI (r1v9 float) = (r1v5 float), (r1v14 float) binds: [B:28:0x0098, B:21:0x007e] A[DONT_GENERATE, DONT_INLINE]] */
    @Override // kotlin.jvm.functions.Function1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r10) {
        /*
            Method dump skipped, instructions count: 324
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.n1.invoke(java.lang.Object):java.lang.Object");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n1(o1 o1Var, float f, Function1 function1) {
        super(1);
        this.a = 0;
        this.c = o1Var;
        this.b = f;
        this.d = function1;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n1(androidx.compose.ui.layout.W w, U4 u4, float f) {
        super(1);
        this.a = 3;
        this.c = w;
        this.d = u4;
        this.b = f;
    }
}
