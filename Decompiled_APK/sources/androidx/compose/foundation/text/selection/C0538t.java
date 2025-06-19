package androidx.compose.foundation.text.selection;

import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.foundation.text.selection.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0538t extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ C0534o a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ I d;
    public final /* synthetic */ Object e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0538t(C0534o c0534o, int i, int i2, I i3, kotlin.k kVar) {
        super(0);
        this.a = c0534o;
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = kVar;
    }

    /* JADX WARN: Type inference failed for: r1v0, types: [java.lang.Object, kotlin.k] */
    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        int iIntValue = ((Number) this.e.getValue()).intValue();
        I i = this.d;
        boolean zB = i.b();
        boolean z = i.j() == 1;
        C0534o c0534o = this.a;
        androidx.compose.ui.text.H h = c0534o.f;
        int i2 = this.b;
        long jL = h.l(i2);
        int i3 = androidx.compose.ui.text.K.c;
        int i4 = (int) (jL >> 32);
        androidx.compose.ui.text.H h2 = c0534o.f;
        int iF = h2.f(i4);
        int i5 = h2.b.f;
        if (iF != iIntValue) {
            i4 = iIntValue >= i5 ? h2.i(i5 - 1) : h2.i(iIntValue);
        }
        int iE = (int) (jL & 4294967295L);
        if (h2.f(iE) != iIntValue) {
            iE = iIntValue >= i5 ? h2.e(i5 - 1, false) : h2.e(iIntValue, false);
        }
        int i6 = this.c;
        if (i4 == i6) {
            return c0534o.a(iE);
        }
        if (iE == i6) {
            return c0534o.a(i4);
        }
        if (!(zB ^ z) ? i2 >= i4 : i2 > iE) {
            i4 = iE;
        }
        return c0534o.a(i4);
    }
}
