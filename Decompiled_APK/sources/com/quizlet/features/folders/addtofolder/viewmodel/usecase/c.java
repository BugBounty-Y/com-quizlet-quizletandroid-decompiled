package com.quizlet.features.folders.addtofolder.viewmodel.usecase;

import androidx.compose.animation.C0297y;
import androidx.compose.foundation.gestures.l1;
import androidx.datastore.core.C1087t;
import androidx.paging.C1319i;
import androidx.paging.J0;
import androidx.work.impl.model.e;
import java.util.ArrayList;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.flow.InterfaceC5002j;
import kotlinx.coroutines.flow.V;
import kotlinx.coroutines.flow.internal.AbstractC4994b;
import kotlinx.coroutines.flow.internal.w;

/* loaded from: classes3.dex */
public final class c implements InterfaceC4992i {
    public final /* synthetic */ int a;
    public final /* synthetic */ InterfaceC4992i b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;

    public /* synthetic */ c(InterfaceC4992i interfaceC4992i, Object obj, Object obj2, int i) {
        this.a = i;
        this.b = interfaceC4992i;
        this.c = obj;
        this.d = obj2;
    }

    /* JADX WARN: Type inference failed for: r2v0, types: [java.lang.Object, kotlin.jvm.functions.c] */
    @Override // kotlinx.coroutines.flow.InterfaceC4992i
    public final Object b(InterfaceC5002j interfaceC5002j, h hVar) {
        Object obj = this.c;
        InterfaceC4992i interfaceC4992i = this.b;
        ?? r2 = this.d;
        switch (this.a) {
            case 0:
                Object objB = ((J0) interfaceC4992i).b(new C0297y(interfaceC5002j, (l1) obj, (ArrayList) r2, 6), hVar);
                if (objB != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            case 1:
                Object objB2 = interfaceC4992i.b(new C0297y(interfaceC5002j, (String) obj, (e) r2, 7), hVar);
                if (objB2 != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            case 2:
                Object objA = AbstractC4994b.a(hVar, V.a, new C1319i((kotlin.jvm.functions.c) r2, (h) null), interfaceC5002j, new InterfaceC4992i[]{interfaceC4992i, (InterfaceC4992i) obj});
                if (objA != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
            default:
                Object objM = E.m(new w((C1087t) interfaceC4992i, (com.quizlet.analytics.marketing.appsflyer.d) obj, interfaceC5002j, (com.quizlet.qutils.coroutines.a) r2, null), hVar);
                if (objM != kotlin.coroutines.intrinsics.a.a) {
                    break;
                }
                break;
        }
        return Unit.a;
    }
}
