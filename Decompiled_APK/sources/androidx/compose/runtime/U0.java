package androidx.compose.runtime;

import androidx.camera.camera2.internal.C0132i;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes.dex */
public final class U0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public androidx.collection.J j;
    public Function1 k;
    public kotlinx.coroutines.channels.l l;
    public C0132i m;
    public Object n;
    public int o;
    public /* synthetic */ Object p;
    public final /* synthetic */ Function0 q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public U0(Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.q = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        U0 u0 = new U0(this.q, hVar);
        u0.p = obj;
        return u0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Throwable {
        ((U0) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:125:0x01a2, code lost:
    
        r6 = r18;
        r2 = r19;
     */
    /* JADX WARN: Finally extract failed */
    /* JADX WARN: Removed duplicated region for block: B:120:0x00df A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:126:0x0165 A[EDGE_INSN: B:126:0x0165->B:70:0x0165 BREAK  A[LOOP:0: B:38:0x00dd->B:97:0x01bf], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00da A[Catch: all -> 0x0027, PHI: r0 r2 r4 r5 r6 r7 r8 r9 r10 r11
  0x00da: PHI (r0v6 int) = (r0v27 int), (r0v0 int) binds: [B:34:0x00d6, B:16:0x0043] A[DONT_GENERATE, DONT_INLINE]
  0x00da: PHI (r2v1 boolean) = (r2v12 boolean), (r2v0 boolean) binds: [B:34:0x00d6, B:16:0x0043] A[DONT_GENERATE, DONT_INLINE]
  0x00da: PHI (r4v8 java.lang.Object) = (r4v11 java.lang.Object), (r4v14 java.lang.Object) binds: [B:34:0x00d6, B:16:0x0043] A[DONT_GENERATE, DONT_INLINE]
  0x00da: PHI (r5v1 int) = (r5v15 int), (r5v0 int) binds: [B:34:0x00d6, B:16:0x0043] A[DONT_GENERATE, DONT_INLINE]
  0x00da: PHI (r6v8 androidx.camera.camera2.internal.i) = (r6v24 androidx.camera.camera2.internal.i), (r6v27 androidx.camera.camera2.internal.i) binds: [B:34:0x00d6, B:16:0x0043] A[DONT_GENERATE, DONT_INLINE]
  0x00da: PHI (r7v2 kotlinx.coroutines.channels.l) = (r7v3 kotlinx.coroutines.channels.l), (r7v6 kotlinx.coroutines.channels.l) binds: [B:34:0x00d6, B:16:0x0043] A[DONT_GENERATE, DONT_INLINE]
  0x00da: PHI (r8v1 kotlin.jvm.functions.Function1) = (r8v2 kotlin.jvm.functions.Function1), (r8v5 kotlin.jvm.functions.Function1) binds: [B:34:0x00d6, B:16:0x0043] A[DONT_GENERATE, DONT_INLINE]
  0x00da: PHI (r9v1 androidx.collection.J) = (r9v2 androidx.collection.J), (r9v5 androidx.collection.J) binds: [B:34:0x00d6, B:16:0x0043] A[DONT_GENERATE, DONT_INLINE]
  0x00da: PHI (r10v2 kotlinx.coroutines.flow.j) = (r10v3 kotlinx.coroutines.flow.j), (r10v8 kotlinx.coroutines.flow.j) binds: [B:34:0x00d6, B:16:0x0043] A[DONT_GENERATE, DONT_INLINE]
  0x00da: PHI (r11v5 java.lang.Object) = (r11v10 java.lang.Object), (r11v11 java.lang.Object) binds: [B:34:0x00d6, B:16:0x0043] A[DONT_GENERATE, DONT_INLINE], TRY_LEAVE, TryCatch #2 {all -> 0x0027, blocks: (B:8:0x001f, B:33:0x00c4, B:36:0x00da, B:79:0x0192, B:95:0x01bb, B:96:0x01be, B:15:0x0040, B:18:0x0055, B:25:0x0095, B:29:0x00aa, B:102:0x01ce, B:103:0x01d1, B:26:0x009f, B:28:0x00a7, B:99:0x01c9, B:100:0x01cc), top: B:113:0x0009, inners: #7 }] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x0150  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x0167 A[Catch: all -> 0x01a8, TRY_LEAVE, TryCatch #5 {all -> 0x01a8, blocks: (B:50:0x011f, B:68:0x0158, B:71:0x0167, B:75:0x017f, B:77:0x0188, B:54:0x012a, B:60:0x0139), top: B:118:0x011f }] */
    /* JADX WARN: Removed duplicated region for block: B:86:0x01aa  */
    /* JADX WARN: Removed duplicated region for block: B:97:0x01bf A[LOOP:0: B:38:0x00dd->B:97:0x01bf, LOOP_END] */
    /* JADX WARN: Type inference failed for: r11v0, types: [java.lang.Object, java.util.Collection] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:82:0x01a1 -> B:83:0x01a2). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r25) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 473
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.runtime.U0.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
