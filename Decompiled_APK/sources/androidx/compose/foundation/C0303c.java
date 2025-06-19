package androidx.compose.foundation;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0303c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public androidx.compose.foundation.interaction.o j;
    public int k;
    public final /* synthetic */ AbstractC0368j l;
    public final /* synthetic */ long m;
    public final /* synthetic */ androidx.compose.foundation.interaction.l n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0303c(AbstractC0368j abstractC0368j, long j, androidx.compose.foundation.interaction.l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = abstractC0368j;
        this.m = j;
        this.n = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C0303c(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0303c) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:85:0x0133, code lost:
    
        if (r16.n.c(r1, r16) == r3) goto L86;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0117  */
    /* JADX WARN: Type inference failed for: r11v22 */
    /* JADX WARN: Type inference failed for: r11v7 */
    /* JADX WARN: Type inference failed for: r11v8, types: [androidx.compose.ui.p] */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r17) {
        /*
            Method dump skipped, instructions count: 323
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.C0303c.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
