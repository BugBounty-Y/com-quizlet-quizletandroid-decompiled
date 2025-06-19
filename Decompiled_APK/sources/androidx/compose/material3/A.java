package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class A extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.ui.q a;
    public final /* synthetic */ androidx.compose.runtime.internal.d b;
    public final /* synthetic */ androidx.compose.ui.text.L c;
    public final /* synthetic */ float d;
    public final /* synthetic */ androidx.compose.runtime.internal.d e;
    public final /* synthetic */ androidx.compose.ui.text.L f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ androidx.compose.runtime.internal.d h;
    public final /* synthetic */ float i;
    public final /* synthetic */ float j;
    public final /* synthetic */ androidx.compose.foundation.layout.R0 k;
    public final /* synthetic */ V4 l;
    public final /* synthetic */ com.quizlet.data.repository.achievements.h m;
    public final /* synthetic */ int n;
    public final /* synthetic */ int o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(androidx.compose.ui.q qVar, androidx.compose.runtime.internal.d dVar, androidx.compose.ui.text.L l, float f, androidx.compose.runtime.internal.d dVar2, androidx.compose.ui.text.L l2, androidx.compose.runtime.internal.d dVar3, androidx.compose.runtime.internal.d dVar4, float f2, float f3, androidx.compose.foundation.layout.R0 r0, V4 v4, com.quizlet.data.repository.achievements.h hVar, int i, int i2) {
        super(2);
        this.a = qVar;
        this.b = dVar;
        this.c = l;
        this.d = f;
        this.e = dVar2;
        this.f = l2;
        this.g = dVar3;
        this.h = dVar4;
        this.i = f2;
        this.j = f3;
        this.k = r0;
        this.l = v4;
        this.m = hVar;
        this.n = i;
        this.o = i2;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.n | 1);
        int iH2 = C0776c.H(this.o);
        androidx.compose.runtime.internal.d dVar = this.b;
        androidx.compose.runtime.internal.d dVar2 = this.e;
        androidx.compose.foundation.layout.R0 r0 = this.k;
        V4 v4 = this.l;
        D.f(this.a, dVar, this.c, this.d, dVar2, this.f, this.g, this.h, this.i, this.j, r0, v4, this.m, (InterfaceC0806l) obj, iH, iH2);
        return Unit.a;
    }
}
