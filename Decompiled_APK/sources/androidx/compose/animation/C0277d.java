package androidx.compose.animation;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.animation.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0277d extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ Object a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ androidx.compose.ui.i d;
    public final /* synthetic */ String e;
    public final /* synthetic */ C0229c f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ int h;
    public final /* synthetic */ int i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0277d(Object obj, androidx.compose.ui.q qVar, Function1 function1, androidx.compose.ui.i iVar, String str, C0229c c0229c, androidx.compose.runtime.internal.d dVar, int i, int i2) {
        super(2);
        this.a = obj;
        this.b = qVar;
        this.c = function1;
        this.d = iVar;
        this.e = str;
        this.f = c0229c;
        this.g = dVar;
        this.h = i;
        this.i = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.h | 1);
        androidx.compose.runtime.internal.d dVar = this.g;
        String str = this.e;
        E.b(this.a, this.b, this.c, this.d, str, this.f, dVar, (InterfaceC0806l) obj, iH, this.i);
        return Unit.a;
    }
}
