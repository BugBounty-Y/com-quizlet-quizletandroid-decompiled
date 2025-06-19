package androidx.compose.foundation.text.selection;

import androidx.compose.ui.platform.ChoreographerFrameCallbackC0931a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class n0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ n0(int i, Object obj, Object obj2) {
        super(1);
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    private final Object a(Object obj) {
        androidx.compose.ui.platform.Z z = (androidx.compose.ui.platform.Z) this.b;
        ChoreographerFrameCallbackC0931a0 choreographerFrameCallbackC0931a0 = (ChoreographerFrameCallbackC0931a0) this.c;
        synchronized (z.d) {
            z.f.remove(choreographerFrameCallbackC0931a0);
        }
        return Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:180:0x034a  */
    /* JADX WARN: Removed duplicated region for block: B:193:0x0383 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:194:0x0384  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x038c A[RETURN] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final java.lang.Object b(java.lang.Object r18) {
        /*
            Method dump skipped, instructions count: 909
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.n0.b(java.lang.Object):java.lang.Object");
    }

    private final Object d(Object obj) {
        androidx.compose.ui.text.font.H h = (androidx.compose.ui.text.font.H) obj;
        com.quizlet.data.repository.activitycenter.b bVar = (com.quizlet.data.repository.activitycenter.b) this.b;
        com.google.android.gms.internal.mlkit_common.u uVar = (com.google.android.gms.internal.mlkit_common.u) bVar.b;
        androidx.compose.ui.text.font.E e = (androidx.compose.ui.text.font.E) this.c;
        synchronized (uVar) {
            try {
                if (h.c()) {
                    ((androidx.compose.ui.text.caches.b) bVar.c).e(e, h);
                } else {
                    ((androidx.compose.ui.text.caches.b) bVar.c).h(e);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        return Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:244:0x060d  */
    /* JADX WARN: Type inference failed for: r3v5, types: [java.lang.Object, java.util.Map] */
    @Override // kotlin.jvm.functions.Function1
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object invoke(java.lang.Object r19) {
        /*
            Method dump skipped, instructions count: 1668
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.text.selection.n0.invoke(java.lang.Object):java.lang.Object");
    }
}
