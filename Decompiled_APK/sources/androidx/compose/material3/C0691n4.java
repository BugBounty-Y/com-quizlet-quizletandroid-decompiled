package androidx.compose.material3;

import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.InterfaceC0806l;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.material3.n4, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0691n4 extends kotlin.jvm.internal.r implements Function2 {
    public final /* synthetic */ int a = 1;
    public final /* synthetic */ boolean b;
    public final /* synthetic */ Function0 c;
    public final /* synthetic */ boolean d;
    public final /* synthetic */ long e;
    public final /* synthetic */ long f;
    public final /* synthetic */ androidx.compose.runtime.internal.d g;
    public final /* synthetic */ int h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0691n4(boolean z, Function0 function0, boolean z2, long j, long j2, androidx.compose.runtime.internal.d dVar, int i) {
        super(2);
        this.b = z;
        this.c = function0;
        this.d = z2;
        this.e = j;
        this.f = j2;
        this.g = dVar;
        this.h = i;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                ((Number) obj2).intValue();
                int iH = C0776c.H(this.h | 1);
                androidx.compose.runtime.internal.d dVar = this.g;
                long j = this.e;
                boolean z = this.b;
                AbstractC0709q4.b(iH, j, this.f, (InterfaceC0806l) obj, dVar, this.c, z, this.d);
                break;
            default:
                ((Number) obj2).intValue();
                int iH2 = C0776c.H(this.h | 1);
                androidx.compose.runtime.internal.d dVar2 = this.g;
                long j2 = this.e;
                long j3 = this.f;
                AbstractC0709q4.a(iH2, j2, j3, (InterfaceC0806l) obj, dVar2, this.c, this.b, this.d);
                break;
        }
        return Unit.a;
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0691n4(boolean z, Function0 function0, boolean z2, androidx.compose.runtime.internal.d dVar, long j, long j2, int i) {
        super(2);
        this.b = z;
        this.c = function0;
        this.d = z2;
        this.g = dVar;
        this.e = j;
        this.f = j2;
        this.h = i;
    }
}
