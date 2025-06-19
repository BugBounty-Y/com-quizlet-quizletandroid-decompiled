package com.quizlet.learn.ui.toolbar;

import androidx.compose.runtime.H0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ d j;
    public final /* synthetic */ com.google.firebase.crashlytics.internal.common.i k;
    public final /* synthetic */ H0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(d dVar, com.google.firebase.crashlytics.internal.common.i iVar, H0 h0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = dVar;
        this.k = iVar;
        this.l = h0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (((a) this.j).a != null) {
            int i = (int) ((r5.a / r5.b) * 100);
            H0 h0 = this.l;
            if (i <= h0.i()) {
                h0.j(i);
                com.google.firebase.crashlytics.internal.common.i iVar = this.k;
                if (iVar != null) {
                    iVar.run();
                }
            } else {
                h0.j(i);
            }
        }
        return Unit.a;
    }
}
