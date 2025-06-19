package com.quizlet.features.achievements.notification;

import androidx.glance.appwidget.protobuf.Z;
import com.onetrust.otpublishers.headless.UI.fragment.q;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class d extends i implements Function2 {
    public int j;
    public final /* synthetic */ f k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(f fVar, h hVar) {
        super(2, hVar);
        this.k = fVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
            if (i == 0) {
                Z.e(obj);
                q qVar = this.k.b;
                this.j = 1;
                com.quizlet.data.repository.achievements.h hVar = (com.quizlet.data.repository.achievements.h) qVar.b;
                hVar.getClass();
                Object objJ = E.J((AbstractC5040y) hVar.c, new com.quizlet.data.repository.achievements.a(hVar, null), this);
                if (objJ != kotlin.coroutines.intrinsics.a.a) {
                    objJ = Unit.a;
                }
                if (objJ != obj2) {
                    objJ = Unit.a;
                }
                if (objJ == obj2) {
                    return obj2;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
        } catch (Exception e) {
            timber.log.c.a.d("Failed to clear notifications: " + e, new Object[0]);
        }
        return Unit.a;
    }
}
