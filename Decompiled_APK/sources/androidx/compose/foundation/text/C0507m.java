package androidx.compose.foundation.text;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0507m extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ C0995g a;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ androidx.compose.ui.text.L c;
    public final /* synthetic */ Function1 d;
    public final /* synthetic */ int e;
    public final /* synthetic */ boolean f;
    public final /* synthetic */ int g;
    public final /* synthetic */ int h;
    public final /* synthetic */ Map i;
    public final /* synthetic */ int j;
    public final /* synthetic */ int k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0507m(C0995g c0995g, androidx.compose.ui.q qVar, androidx.compose.ui.text.L l, Function1 function1, int i, boolean z, int i2, int i3, Map map, int i4, int i5) {
        super(2);
        this.a = c0995g;
        this.b = qVar;
        this.c = l;
        this.d = function1;
        this.e = i;
        this.f = z;
        this.g = i2;
        this.h = i3;
        this.i = map;
        this.j = i4;
        this.k = i5;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.j | 1);
        int i = this.h;
        AbstractC0484d0.a(this.a, this.b, this.c, this.d, this.e, this.f, this.g, i, this.i, (InterfaceC0806l) obj, iH, this.k);
        return Unit.a;
    }
}
