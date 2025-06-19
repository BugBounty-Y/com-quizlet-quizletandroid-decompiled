package androidx.compose.ui.window;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ u l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(u uVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        i iVar = new i(this.l, hVar);
        iVar.k = obj;
        return iVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Path cross not found for [B:18:0x005a, B:20:0x005e], limit reached: 25 */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0027  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0068  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:14:0x0045 -> B:16:0x0048). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r9) {
        /*
            r8 = this;
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r8.j
            r2 = 1
            if (r1 == 0) goto L19
            if (r1 != r2) goto L11
            java.lang.Object r1 = r8.k
            kotlinx.coroutines.C r1 = (kotlinx.coroutines.C) r1
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L48
        L11:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r0)
            throw r9
        L19:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            java.lang.Object r9 = r8.k
            kotlinx.coroutines.C r9 = (kotlinx.coroutines.C) r9
            r1 = r9
        L21:
            boolean r9 = kotlinx.coroutines.E.x(r1)
            if (r9 == 0) goto L68
            androidx.compose.ui.window.c r9 = androidx.compose.ui.window.c.c
            r8.k = r1
            r8.j = r2
            kotlin.coroutines.CoroutineContext r3 = r8.getContext()
            androidx.compose.ui.platform.v0 r4 = androidx.compose.ui.platform.C0972v0.a
            kotlin.coroutines.CoroutineContext$Element r3 = r3.get(r4)
            if (r3 != 0) goto L62
            kotlin.coroutines.CoroutineContext r3 = r8.getContext()
            androidx.compose.runtime.W r3 = androidx.compose.runtime.C0776c.r(r3)
            java.lang.Object r9 = r3.P(r9, r8)
            if (r9 != r0) goto L48
            return r0
        L48:
            androidx.compose.ui.window.u r9 = r8.l
            int[] r3 = r9.s
            r4 = 0
            r5 = r3[r4]
            r6 = r3[r2]
            android.view.View r7 = r9.d
            r7.getLocationOnScreen(r3)
            r4 = r3[r4]
            if (r5 != r4) goto L5e
            r3 = r3[r2]
            if (r6 == r3) goto L21
        L5e:
            r9.g()
            goto L21
        L62:
            java.lang.ClassCastException r9 = new java.lang.ClassCastException
            r9.<init>()
            throw r9
        L68:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.window.i.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
