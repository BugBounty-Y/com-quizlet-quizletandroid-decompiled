package androidx.compose.foundation.text.selection;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.selection.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0523d extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ InterfaceC0533n a;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ androidx.compose.ui.text.style.h c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ long e;
    public final /* synthetic */ androidx.compose.ui.q f;
    public final /* synthetic */ int g;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0523d(InterfaceC0533n interfaceC0533n, boolean z, androidx.compose.ui.text.style.h hVar, boolean z2, long j, androidx.compose.ui.q qVar, int i) {
        super(2);
        this.a = interfaceC0533n;
        this.b = z;
        this.c = hVar;
        this.d = z2;
        this.e = j;
        this.f = qVar;
        this.g = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.g | 1);
        androidx.compose.ui.text.style.h hVar = this.c;
        boolean z = this.d;
        W.d(this.a, this.b, hVar, z, this.e, this.f, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
