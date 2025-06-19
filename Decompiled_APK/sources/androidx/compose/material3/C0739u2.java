package androidx.compose.material3;

import androidx.compose.material3.internal.C0659x;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.material3.u2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0739u2 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ float a;
    public final /* synthetic */ long b;
    public final /* synthetic */ F3 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0739u2(float f, long j, F3 f3) {
        super(1);
        this.a = f;
        this.b = j;
        this.c = f3;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        C0659x c0659x = (C0659x) obj;
        G3 g3 = G3.a;
        float f = this.a;
        c0659x.a(g3, f);
        int i = (int) (this.b & 4294967295L);
        float f2 = i;
        if (f2 > f / 2 && !this.c.a) {
            c0659x.a(G3.c, f / 2.0f);
        }
        if (i != 0) {
            c0659x.a(G3.b, Math.max(DefinitionKt.NO_Float_VALUE, f - f2));
        }
        return Unit.a;
    }
}
