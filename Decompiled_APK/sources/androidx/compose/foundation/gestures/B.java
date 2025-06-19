package androidx.compose.foundation.gestures;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class B extends kotlin.coroutines.jvm.internal.h implements Function2 {
    public androidx.compose.ui.input.pointer.f k;
    public int l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ kotlin.jvm.internal.J o;
    public final /* synthetic */ kotlin.jvm.internal.J p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(kotlin.jvm.internal.J j, kotlin.jvm.internal.J j2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = j;
        this.p = j2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        B b = new B(this.o, this.p, hVar);
        b.n = obj;
        return b;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((androidx.compose.ui.input.pointer.z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:30:0x0092, code lost:
    
        r2 = r3;
     */
    /* JADX WARN: Removed duplicated region for block: B:12:0x003d  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0059  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0073  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00a4  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00b2  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00d5  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x00fa  */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0123  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00c3 A[EDGE_INSN: B:66:0x00c3->B:41:0x00c3 BREAK  A[LOOP:0: B:36:0x00b0->B:40:0x00c0], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:70:0x0069 A[SYNTHETIC] */
    /* JADX WARN: Type inference failed for: r5v9, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r7v5, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r9v0, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r9v1, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:34:0x00a4 -> B:35:0x00a7). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r17) {
        /*
            Method dump skipped, instructions count: 294
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.B.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
