package com.quizlet.local.datastore.preferences;

import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: com.quizlet.local.datastore.preferences.x, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4587x implements InterfaceC4992i {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC4992i b;
    public final /* synthetic */ androidx.datastore.preferences.core.f c;

    public /* synthetic */ C4587x(InterfaceC4992i interfaceC4992i, androidx.datastore.preferences.core.f fVar, int i) {
        this.a = i;
        this.b = interfaceC4992i;
        this.c = fVar;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                Object objB = this.b.b(new C4586w(interfaceC5002j, this.c, 0), hVar);
                if (objB != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            case 1:
                Object objB2 = this.b.b(new C4586w(interfaceC5002j, this.c, 2), hVar);
                if (objB2 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objB3 = this.b.b(new C4586w(interfaceC5002j, this.c, 3), hVar);
                if (objB3 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }
}
