package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.user.LoggedInRequiredException;
import com.quizlet.db.data.caches.UserInfoCache;
import com.quizlet.generated.enums.EnumC4467b;
import com.quizlet.generated.enums.EnumC4491j;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class G extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G(P p, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new G(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((G) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            P p = this.k;
            androidx.compose.foundation.text.input.internal.u uVar = p.I;
            String strValueOf = String.valueOf(p.D());
            this.j = 1;
            if (!((UserInfoCache) uVar.c).b()) {
                throw new LoggedInRequiredException();
            }
            Object objH = ((com.quizlet.data.repository.achievements.h) uVar.b).h(EnumC4491j.SETS, EnumC4467b.STUDY, strValueOf, this);
            if (objH != aVar) {
                objH = Unit.a;
            }
            if (objH == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
