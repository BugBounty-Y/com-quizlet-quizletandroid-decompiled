package com.quizlet.features.setpage.termlist.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import java.io.Serializable;
import java.util.List;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class f extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public InterfaceC0773a0 j;
    public int k;
    public final /* synthetic */ io.ktor.client.plugins.api.d l;
    public final /* synthetic */ InterfaceC0773a0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(io.ktor.client.plugins.api.d dVar, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = dVar;
        this.m = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        InterfaceC0773a0 interfaceC0773a0;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                InterfaceC0773a0 interfaceC0773a02 = this.m;
                io.ktor.client.plugins.api.d dVar = this.l;
                this.j = interfaceC0773a02;
                this.k = 1;
                Serializable serializableV = dVar.v(this);
                if (serializableV == aVar) {
                    return aVar;
                }
                interfaceC0773a0 = interfaceC0773a02;
                obj = serializableV;
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                interfaceC0773a0 = this.j;
                Z.e(obj);
            }
            interfaceC0773a0.setValue((List) obj);
        } catch (Exception e) {
            timber.log.c.a.c(e, "Failed to load ads", new Object[0]);
        }
        return Unit.a;
    }
}
