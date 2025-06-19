package androidx.paging;

import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: androidx.paging.b0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1306b0 implements InterfaceC4992i {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ InterfaceC4992i c;

    public /* synthetic */ C1306b0(InterfaceC4992i interfaceC4992i, int i, int i2) {
        this.a = i2;
        this.c = interfaceC4992i;
        this.b = i;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                Object objB = ((C1306b0) this.c).b(new C1304a0(interfaceC5002j, this.b, 0), hVar);
                if (objB != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objB2 = this.c.b(new kotlinx.coroutines.flow.C(new kotlin.jvm.internal.H(), this.b, interfaceC5002j), hVar);
                if (objB2 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }
}
