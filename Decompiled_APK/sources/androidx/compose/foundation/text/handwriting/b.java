package androidx.compose.foundation.text.handwriting;

import androidx.compose.ui.input.pointer.g;
import androidx.compose.ui.input.pointer.n;
import androidx.compose.ui.input.pointer.z;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.h;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class b extends h implements Function2 {
    public n k;
    public g l;
    public int m;
    public /* synthetic */ Object n;
    public final /* synthetic */ d o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.o = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        b bVar = new b(this.o, hVar);
        bVar.n = obj;
        return bVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((z) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Code restructure failed: missing block: B:13:0x0054, code lost:
    
        if (r10 == r1) goto L66;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00bc, code lost:
    
        if (r11 != r1) goto L40;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x0141, code lost:
    
        if (r5 != r1) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x0143, code lost:
    
        return r1;
     */
    /* JADX WARN: Path cross not found for [B:56:0x0103, B:54:0x00f2], limit reached: 89 */
    /* JADX WARN: Type inference failed for: r11v8, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Type inference failed for: r5v12, types: [java.lang.Object, java.util.List] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:38:0x00bc -> B:40:0x00c0). Please report as a decompilation issue!!! */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:65:0x0141 -> B:67:0x0144). Please report as a decompilation issue!!! */
    @Override // kotlin.coroutines.jvm.internal.a
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invokeSuspend(java.lang.Object r19) {
        /*
            Method dump skipped, instructions count: 388
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.handwriting.b.invokeSuspend(java.lang.Object):java.lang.Object");
    }
}
