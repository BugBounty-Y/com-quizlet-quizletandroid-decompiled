package com.quizlet.quizletandroid.ui;

import android.content.Intent;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.features.emailconfirmation.ui.activities.EmailConfirmationActivity;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ RootActivity k;
    public final /* synthetic */ Intent[] l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(RootActivity rootActivity, Intent[] intentArr, h hVar) {
        super(2, hVar);
        this.k = rootActivity;
        this.l = intentArr;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        RootActivity rootActivity = this.k;
        if (i == 0) {
            Z.e(obj);
            com.google.firebase.crashlytics.internal.settings.b bVar = rootActivity.l;
            if (bVar == null) {
                Intrinsics.m("requireEmailConfirmationFeature");
                throw null;
            }
            this.j = 1;
            obj = bVar.d(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        boolean zBooleanValue = ((Boolean) obj).booleanValue();
        Intent[] intentArr = this.l;
        if (zBooleanValue) {
            int i2 = RootActivity.o;
            rootActivity.getClass();
            String str = EmailConfirmationActivity.r;
            rootActivity.startActivity(T.b(rootActivity, intentArr));
        } else {
            rootActivity.startActivities(intentArr);
        }
        rootActivity.finish();
        return Unit.a;
    }
}
