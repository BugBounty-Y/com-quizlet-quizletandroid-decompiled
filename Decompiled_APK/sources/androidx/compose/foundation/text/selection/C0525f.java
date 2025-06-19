package androidx.compose.foundation.text.selection;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.selection.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0525f extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ int c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0525f(boolean z, androidx.compose.ui.q qVar, Function0 function0, int i) {
        super(2);
        this.d = qVar;
        this.e = function0;
        this.b = z;
        this.c = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i = this.a;
        InterfaceC0806l interfaceC0806l = (InterfaceC0806l) obj;
        ((Number) obj2).intValue();
        switch (i) {
            case 0:
                W.e(C0776c.H(this.c | 1), interfaceC0806l, (androidx.compose.ui.q) this.d, (Function0) this.e, this.b);
                break;
            default:
                int iH = C0776c.H(this.c | 1);
                W.g(this.b, (androidx.compose.ui.text.style.h) this.d, (i0) this.e, interfaceC0806l, iH);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0525f(boolean z, androidx.compose.ui.text.style.h hVar, i0 i0Var, int i) {
        super(2);
        this.b = z;
        this.d = hVar;
        this.e = i0Var;
        this.c = i;
    }
}
