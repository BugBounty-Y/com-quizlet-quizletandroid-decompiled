package com.quizlet.upgrade.upsell.ui;

import android.content.Context;
import android.content.Intent;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3242q6;
import com.quizlet.upgrade.ui.activity.UpgradeActivity;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public final /* synthetic */ UpsellModalFragment j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(UpsellModalFragment upsellModalFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = upsellModalFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        UpsellModalFragment upsellModalFragment = this.j;
        String str = UpgradeActivity.v;
        Context contextRequireContext = upsellModalFragment.requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        Intent intentI = AbstractC3242q6.i(contextRequireContext, (String) upsellModalFragment.Y.getValue(), (com.quizlet.features.infra.models.upgrade.a) upsellModalFragment.Z.getValue());
        androidx.activity.result.b bVar = upsellModalFragment.L;
        if (bVar != null) {
            bVar.a(intentI);
            return Unit.a;
        }
        Intrinsics.m("upgradeResultLauncher");
        throw null;
    }
}
