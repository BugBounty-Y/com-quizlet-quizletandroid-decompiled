package com.quizlet.local.datastore.preferences;

import androidx.compose.foundation.gestures.l1;
import androidx.paging.J0;
import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* renamed from: com.quizlet.local.datastore.preferences.p, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4580p implements InterfaceC4992i {
    public final /* synthetic */ int a;
    public final /* synthetic */ long b;
    public final /* synthetic */ InterfaceC4992i c;
    public final /* synthetic */ Object d;

    public /* synthetic */ C4580p(InterfaceC4992i interfaceC4992i, Object obj, long j, int i) {
        this.a = i;
        this.c = interfaceC4992i;
        this.d = obj;
        this.b = j;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, kotlin.coroutines.h hVar) {
        switch (this.a) {
            case 0:
                Object objB = this.c.b(new C4579o(interfaceC5002j, (l1) this.d, this.b, 0), hVar);
                if (objB != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objB2 = ((J0) this.c).b(new C4579o(interfaceC5002j, (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.G) this.d, this.b, 1), hVar);
                if (objB2 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }
}
