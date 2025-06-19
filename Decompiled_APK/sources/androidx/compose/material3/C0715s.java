package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0715s extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ androidx.compose.ui.text.L c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ androidx.compose.runtime.internal.d f;
    public final /* synthetic */ float g;
    public final /* synthetic */ androidx.compose.foundation.layout.R0 h;
    public final /* synthetic */ V4 i;
    public final /* synthetic */ int j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0715s(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.text.L l, boolean z, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, float f, androidx.compose.foundation.layout.R0 r0, V4 v4, int i) {
        super(2);
        this.a = qVar;
        this.b = dVar;
        this.c = l;
        this.d = z;
        this.e = dVar2;
        this.f = dVar3;
        this.g = f;
        this.h = r0;
        this.i = v4;
        this.j = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.j | 1);
        androidx.compose.runtime.internal.d dVar = this.b;
        androidx.compose.runtime.internal.d dVar2 = this.e;
        androidx.compose.foundation.layout.R0 r0 = this.h;
        V4 v4 = this.i;
        D.d(this.a, dVar, this.c, this.d, dVar2, this.f, this.g, r0, v4, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
