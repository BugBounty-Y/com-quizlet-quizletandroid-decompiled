package com.google.firebase.sessions;

import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_barcode.Q6;
import com.quizlet.features.folders.viewmodel.usecases.LoadFolderException;
import kotlin.Unit;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes2.dex */
public final class H extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;
    public int k;
    public /* synthetic */ InterfaceC5002j l;
    public /* synthetic */ Throwable m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ H(int i, int i2, kotlin.coroutines.h hVar) {
        super(i, hVar);
        this.j = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        InterfaceC5002j interfaceC5002j = (InterfaceC5002j) obj;
        Throwable th = (Throwable) obj2;
        kotlin.coroutines.h hVar = (kotlin.coroutines.h) obj3;
        switch (this.j) {
            case 0:
                H h = new H(3, 0, hVar);
                h.l = interfaceC5002j;
                h.m = th;
                return h.invokeSuspend(Unit.a);
            case 1:
                H h2 = new H(3, 1, hVar);
                h2.l = interfaceC5002j;
                h2.m = th;
                return h2.invokeSuspend(Unit.a);
            case 2:
                H h3 = new H(3, 2, hVar);
                h3.l = interfaceC5002j;
                h3.m = th;
                return h3.invokeSuspend(Unit.a);
            case 3:
                H h4 = new H(3, 3, hVar);
                h4.l = interfaceC5002j;
                h4.m = th;
                return h4.invokeSuspend(Unit.a);
            case 4:
                H h5 = new H(3, 4, hVar);
                h5.l = interfaceC5002j;
                h5.m = th;
                return h5.invokeSuspend(Unit.a);
            default:
                H h6 = new H(3, 5, hVar);
                h6.l = interfaceC5002j;
                h6.m = th;
                return h6.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i = this.k;
                if (i == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    InterfaceC5002j interfaceC5002j = this.l;
                    Log.e("FirebaseSessionsRepo", "Error reading stored session data.", this.m);
                    androidx.datastore.preferences.core.b bVarA = Q6.a();
                    this.l = null;
                    this.k = 1;
                    if (interfaceC5002j.emit(bVarA, this) == aVar) {
                        return aVar;
                    }
                } else {
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 1:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.k;
                if (i2 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    InterfaceC5002j interfaceC5002j2 = this.l;
                    timber.log.c.a.i(this.m, "Failed to load created flashcard sets", new Object[0]);
                    kotlin.collections.K k = kotlin.collections.K.a;
                    this.l = null;
                    this.k = 1;
                    if (interfaceC5002j2.emit(k, this) == aVar2) {
                        return aVar2;
                    }
                } else {
                    if (i2 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 2:
                kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
                int i3 = this.k;
                if (i3 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    InterfaceC5002j interfaceC5002j3 = this.l;
                    Throwable th = this.m;
                    kotlin.p pVar = kotlin.r.b;
                    kotlin.r rVar = new kotlin.r(androidx.glance.appwidget.protobuf.Z.b(new LoadFolderException(th)));
                    this.l = null;
                    this.k = 1;
                    if (interfaceC5002j3.emit(rVar, this) == aVar3) {
                        return aVar3;
                    }
                } else {
                    if (i3 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 3:
                kotlin.coroutines.intrinsics.a aVar4 = kotlin.coroutines.intrinsics.a.a;
                int i4 = this.k;
                if (i4 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    InterfaceC5002j interfaceC5002j4 = this.l;
                    Throwable th2 = this.m;
                    kotlin.p pVar2 = kotlin.r.b;
                    kotlin.r rVar2 = new kotlin.r(androidx.glance.appwidget.protobuf.Z.b(th2));
                    this.l = null;
                    this.k = 1;
                    if (interfaceC5002j4.emit(rVar2, this) == aVar4) {
                        return aVar4;
                    }
                } else {
                    if (i4 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            case 4:
                kotlin.coroutines.intrinsics.a aVar5 = kotlin.coroutines.intrinsics.a.a;
                int i5 = this.k;
                if (i5 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    InterfaceC5002j interfaceC5002j5 = this.l;
                    Throwable th3 = this.m;
                    kotlin.p pVar3 = kotlin.r.b;
                    kotlin.r rVar3 = new kotlin.r(androidx.glance.appwidget.protobuf.Z.b(th3));
                    this.l = null;
                    this.k = 1;
                    if (interfaceC5002j5.emit(rVar3, this) == aVar5) {
                        return aVar5;
                    }
                } else {
                    if (i5 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            default:
                kotlin.coroutines.intrinsics.a aVar6 = kotlin.coroutines.intrinsics.a.a;
                int i6 = this.k;
                if (i6 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    InterfaceC5002j interfaceC5002j6 = this.l;
                    Throwable th4 = this.m;
                    kotlin.p pVar4 = kotlin.r.b;
                    kotlin.r rVar4 = new kotlin.r(androidx.glance.appwidget.protobuf.Z.b(th4));
                    this.l = null;
                    this.k = 1;
                    if (interfaceC5002j6.emit(rVar4, this) == aVar6) {
                        return aVar6;
                    }
                } else {
                    if (i6 != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
        }
    }
}
