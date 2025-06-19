package androidx.compose.material.navigation;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.n;
import com.google.android.gms.internal.mlkit_vision_barcode.E0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function2 {
    public final /* synthetic */ i a;
    public final /* synthetic */ n b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ androidx.compose.foundation.shape.d d;
    public final /* synthetic */ float e;
    public final /* synthetic */ long f;
    public final /* synthetic */ long g;
    public final /* synthetic */ long h;
    public final /* synthetic */ androidx.compose.runtime.internal.d i;
    public final /* synthetic */ int j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(i iVar, n nVar, boolean z, androidx.compose.foundation.shape.d dVar, float f, long j, long j2, long j3, androidx.compose.runtime.internal.d dVar2, int i) {
        super(2);
        this.a = iVar;
        this.b = nVar;
        this.c = z;
        this.d = dVar;
        this.e = f;
        this.f = j;
        this.g = j2;
        this.h = j3;
        this.i = dVar2;
        this.j = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((Number) obj2).intValue();
        int iH = C0776c.H(this.j | 1);
        androidx.compose.runtime.internal.d dVar = this.i;
        long j = this.f;
        long j2 = this.g;
        E0.a(this.a, this.b, this.c, this.d, this.e, j, j2, this.h, dVar, (InterfaceC0806l) obj, iH);
        return Unit.a;
    }
}
