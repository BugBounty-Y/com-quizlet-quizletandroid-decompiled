package androidx.compose.foundation.text;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.text.C0995g;
import java.util.Map;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.text.q, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0515q extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ C0995g b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ Map e;
    public final /* synthetic */ androidx.compose.ui.text.L f;
    public final /* synthetic */ int g;
    public final /* synthetic */ boolean h;
    public final /* synthetic */ int i;
    public final /* synthetic */ int j;
    public final /* synthetic */ androidx.compose.ui.text.font.i k;
    public final /* synthetic */ androidx.compose.foundation.text.modifiers.h l;
    public final /* synthetic */ Function1 m;
    public final /* synthetic */ int n;
    public final /* synthetic */ int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0515q(androidx.compose.ui.q qVar, C0995g c0995g, Function1 function1, boolean z, Map map, androidx.compose.ui.text.L l, int i, boolean z2, int i2, int i3, androidx.compose.ui.text.font.i iVar, androidx.compose.foundation.text.modifiers.h hVar, Function1 function12, int i4, int i5) {
        super(2);
        this.a = qVar;
        this.b = c0995g;
        this.c = function1;
        this.d = z;
        this.e = map;
        this.f = l;
        this.g = i;
        this.h = z2;
        this.i = i2;
        this.j = i3;
        this.k = iVar;
        this.l = hVar;
        this.m = function12;
        this.n = i4;
        this.o = i5;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.n | 1);
        int iH2 = C0776c.H(this.o);
        androidx.compose.ui.text.font.i iVar = this.k;
        androidx.compose.foundation.text.modifiers.h hVar = this.l;
        AbstractC0484d0.h(this.a, this.b, this.c, this.d, this.e, this.f, this.g, this.h, this.i, this.j, iVar, hVar, this.m, (InterfaceC0806l) obj, iH, iH2);
        return Unit.a;
    }
}
