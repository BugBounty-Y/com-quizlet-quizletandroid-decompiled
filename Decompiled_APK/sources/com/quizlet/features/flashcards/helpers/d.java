package com.quizlet.features.flashcards.helpers;

import androidx.datastore.core.C1086s;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class d implements InterfaceC4992i {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC4992i b;

    public /* synthetic */ d(InterfaceC4992i interfaceC4992i, int i) {
        this.a = i;
        this.b = interfaceC4992i;
    }

    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, h hVar) {
        switch (this.a) {
            case 0:
                Object objB = this.b.b(new C1086s(interfaceC5002j, 6), hVar);
                if (objB != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            case 1:
                Object objB2 = this.b.b(new C1086s(interfaceC5002j, 8), hVar);
                if (objB2 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            case 2:
                Object objB3 = this.b.b(new C1086s(interfaceC5002j, 9), hVar);
                if (objB3 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            case 3:
                Object objB4 = this.b.b(new C1086s(interfaceC5002j, 10), hVar);
                if (objB4 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            case 4:
                Object objB5 = this.b.b(new C1086s(interfaceC5002j, 23), hVar);
                if (objB5 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objB6 = this.b.b(new C1086s(interfaceC5002j, 29), hVar);
                if (objB6 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }
}
