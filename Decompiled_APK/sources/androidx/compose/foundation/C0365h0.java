package androidx.compose.foundation;

import androidx.compose.foundation.layout.R0;
import androidx.compose.material3.V4;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.graphics.AbstractC0874w;
import androidx.compose.ui.layout.InterfaceC0889j;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.h0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0365h0 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ androidx.compose.ui.q b;
    public final /* synthetic */ float c;
    public final /* synthetic */ int d;
    public final /* synthetic */ int e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;
    public final /* synthetic */ Object j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0365h0(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, float f, R0 r0, V4 v4, int i, int i2) {
        super(2);
        this.f = dVar;
        this.b = qVar;
        this.g = dVar2;
        this.h = dVar3;
        this.c = f;
        this.i = r0;
        this.j = v4;
        this.d = i;
        this.e = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.d | 1);
                InterfaceC0889j interfaceC0889j = (InterfaceC0889j) this.i;
                AbstractC0460p.c((androidx.compose.ui.graphics.painter.b) this.f, (String) this.g, this.b, (androidx.compose.ui.i) this.h, interfaceC0889j, this.c, (AbstractC0874w) this.j, (InterfaceC0806l) obj, iH, this.e);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.d | 1);
                androidx.compose.runtime.internal.d dVar = (androidx.compose.runtime.internal.d) this.f;
                androidx.compose.runtime.internal.d dVar2 = (androidx.compose.runtime.internal.d) this.g;
                R0 r0 = (R0) this.i;
                androidx.compose.material3.D.a(dVar, this.b, dVar2, (androidx.compose.runtime.internal.d) this.h, this.c, r0, (V4) this.j, (InterfaceC0806l) obj, iH2, this.e);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0365h0(androidx.compose.ui.graphics.painter.b bVar, String str, androidx.compose.ui.q qVar, androidx.compose.ui.i iVar, InterfaceC0889j interfaceC0889j, float f, AbstractC0874w abstractC0874w, int i, int i2) {
        super(2);
        this.f = bVar;
        this.g = str;
        this.b = qVar;
        this.h = iVar;
        this.i = interfaceC0889j;
        this.c = f;
        this.j = abstractC0874w;
        this.d = i;
        this.e = i2;
    }
}
