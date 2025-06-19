package com.quizlet.remote.model.entitlements;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.entitlements.EntitlementException;
import com.quizlet.data.repository.classfolder.e;
import com.quizlet.quizletandroid.ui.profile.b;
import com.quizlet.remote.service.k;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ e k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(e eVar, String str, h hVar) {
        super(2, hVar);
        this.k = eVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws EntitlementException {
        RemoteEntitlementData remoteEntitlementData;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        e eVar = this.k;
        if (i == 0) {
            Z.e(obj);
            k kVar = (k) eVar.b;
            this.j = 1;
            obj = kVar.a(this.l, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        EntitlementResponse entitlementResponse = (EntitlementResponse) CollectionsKt.L(((RemoteEntitlementResponse) obj).a);
        if (entitlementResponse == null || (remoteEntitlementData = (RemoteEntitlementData) CollectionsKt.firstOrNull(entitlementResponse.a.a)) == null) {
            throw new EntitlementException("Entitlement data not found");
        }
        return ((b) eVar.c).a(remoteEntitlementData);
    }
}
