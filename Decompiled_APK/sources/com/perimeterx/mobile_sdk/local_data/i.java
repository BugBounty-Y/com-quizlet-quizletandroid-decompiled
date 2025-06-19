package com.perimeterx.mobile_sdk.local_data;

import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class i implements InterfaceC4992i {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC4992i b;
    public final /* synthetic */ String c;

    public /* synthetic */ i(InterfaceC4992i interfaceC4992i, String str, int i) {
        this.a = i;
        this.b = interfaceC4992i;
        this.c = str;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                Object objB = this.b.b(new h(interfaceC5002j, this.c, 0), hVar);
                if (objB != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            case 1:
                Object objB2 = this.b.b(new h(interfaceC5002j, this.c, 1), hVar);
                if (objB2 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            case 2:
                Object objB3 = this.b.b(new h(interfaceC5002j, this.c, 2), hVar);
                if (objB3 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objB4 = this.b.b(new h(interfaceC5002j, this.c, 3), hVar);
                if (objB4 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }
}
