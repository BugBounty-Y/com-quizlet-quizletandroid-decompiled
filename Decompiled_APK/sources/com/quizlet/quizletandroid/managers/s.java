package com.quizlet.quizletandroid.managers;

import android.content.SharedPreferences;
import androidx.glance.appwidget.protobuf.Z;
import com.facebook.AccessToken;
import com.facebook.login.B;
import com.google.android.gms.internal.mlkit_vision_common.E;
import java.util.Date;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class s extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ u k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(u uVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = uVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new s(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((s) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.data.interactor.achievements.f fVar = this.k.v;
            this.j = 1;
            obj = fVar.e(this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        B b = (B) obj;
        b.getClass();
        Date date = AccessToken.l;
        com.facebook.f.f.o().c(null, true);
        E.c(null);
        com.facebook.h.f.u().a(null, true);
        SharedPreferences.Editor editorEdit = b.a.edit();
        editorEdit.putBoolean("express_login_allowed", false);
        editorEdit.apply();
        timber.log.c.a.g("Reset facebook session", new Object[0]);
        return Unit.a;
    }
}
