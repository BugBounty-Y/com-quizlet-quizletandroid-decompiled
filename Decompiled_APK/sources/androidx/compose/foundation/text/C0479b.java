package androidx.compose.foundation.text;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0479b extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0479b(int i, int i2, androidx.compose.ui.q qVar) {
        super(2);
        this.a = qVar;
        this.b = i;
        this.c = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        AbstractC0485e.b(C0776c.H(this.b | 1), this.c, (InterfaceC0806l) obj, this.a);
        return Unit.a;
    }
}
