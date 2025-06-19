package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.p, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0698p extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ androidx.compose.runtime.internal.d a;
    public final /* synthetic */ androidx.compose.ui.n b;
    public final /* synthetic */ androidx.compose.runtime.internal.d c;
    public final /* synthetic */ androidx.compose.runtime.internal.d d;
    public final /* synthetic */ float e;
    public final /* synthetic */ float f;
    public final /* synthetic */ androidx.compose.foundation.layout.R0 g;
    public final /* synthetic */ V4 h;
    public final /* synthetic */ com.quizlet.data.repository.achievements.h i;
    public final /* synthetic */ int j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0698p(androidx.compose.runtime.internal.d dVar, androidx.compose.ui.n nVar, androidx.compose.runtime.internal.d dVar2, androidx.compose.runtime.internal.d dVar3, float f, float f2, androidx.compose.foundation.layout.R0 r0, V4 v4, com.quizlet.data.repository.achievements.h hVar, int i) {
        super(2);
        this.a = dVar;
        this.b = nVar;
        this.c = dVar2;
        this.d = dVar3;
        this.e = f;
        this.f = f2;
        this.g = r0;
        this.h = v4;
        this.i = hVar;
        this.j = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.j | 1);
        androidx.compose.runtime.internal.d dVar = this.a;
        androidx.compose.runtime.internal.d dVar2 = this.c;
        androidx.compose.foundation.layout.R0 r0 = this.g;
        D.c(dVar, this.b, dVar2, this.d, this.e, this.f, r0, this.h, this.i, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
