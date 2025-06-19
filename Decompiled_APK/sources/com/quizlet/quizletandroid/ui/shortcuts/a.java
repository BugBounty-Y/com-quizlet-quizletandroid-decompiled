package com.quizlet.quizletandroid.ui.shortcuts;

import android.content.Intent;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.quizlet.data.model.m2;
import com.quizlet.features.notes.upload.UploadNotesActivity;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public final /* synthetic */ CreateSetShortcutInterstitialActivity j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(CreateSetShortcutInterstitialActivity createSetShortcutInterstitialActivity, h hVar) {
        super(2, hVar);
        this.j = createSetShortcutInterstitialActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        CreateSetShortcutInterstitialActivity createSetShortcutInterstitialActivity = this.j;
        Intent intentA = D4.a(createSetShortcutInterstitialActivity, null);
        int i = UploadNotesActivity.i;
        createSetShortcutInterstitialActivity.startActivities(new Intent[]{intentA, u.i(createSetShortcutInterstitialActivity, m2.b, null, null, null, 28)});
        return Unit.a;
    }
}
