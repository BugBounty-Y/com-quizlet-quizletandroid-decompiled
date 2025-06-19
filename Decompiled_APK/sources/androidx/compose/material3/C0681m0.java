package androidx.compose.material3;

import androidx.compose.material3.internal.AbstractC0655t;
import androidx.compose.material3.internal.C0658w;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import java.util.Locale;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.m0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0681m0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ Long b;
    public final /* synthetic */ Function1 c;
    public final /* synthetic */ AbstractC0655t d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ C0693o0 g;
    public final /* synthetic */ C0658w h;
    public final /* synthetic */ Locale i;
    public final /* synthetic */ C0699p0 j;
    public final /* synthetic */ int k;
    public final /* synthetic */ int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0681m0(androidx.compose.ui.q qVar, Long l, Function1 function1, AbstractC0655t abstractC0655t, androidx.compose.runtime.internal.d dVar, androidx.compose.runtime.internal.d dVar2, C0693o0 c0693o0, C0658w c0658w, Locale locale, C0699p0 c0699p0, int i, int i2) {
        super(2);
        this.a = qVar;
        this.b = l;
        this.c = function1;
        this.d = abstractC0655t;
        this.e = dVar;
        this.f = dVar2;
        this.g = c0693o0;
        this.h = c0658w;
        this.i = locale;
        this.j = c0699p0;
        this.k = i;
        this.l = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.k | 1);
        int iH2 = C0776c.H(this.l);
        C0699p0 c0699p0 = this.j;
        androidx.compose.runtime.internal.d dVar = this.e;
        androidx.compose.runtime.internal.d dVar2 = this.f;
        C0693o0 c0693o0 = this.g;
        C0658w c0658w = this.h;
        AbstractC0687n0.b(this.a, this.b, this.c, this.d, dVar, dVar2, c0693o0, c0658w, this.i, c0699p0, (InterfaceC0806l) obj, iH, iH2);
        return Unit.a;
    }
}
