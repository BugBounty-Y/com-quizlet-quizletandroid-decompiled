package com.quizlet.data.repository.course.membership;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.data.repository.course.exceptions.CourseInstancesException;
import com.quizlet.quizletandroid.ui.setcreation.managers.n;
import io.reactivex.rxjava3.internal.operators.single.g;
import java.util.List;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ c k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(c cVar, h hVar) {
        super(2, hVar);
        this.k = cVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws CourseInstancesException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        c cVar = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                n nVar = (n) cVar.a;
                g gVarG = ((com.quizlet.remote.service.h) nVar.b).a().g(new com.quizlet.quizletandroid.ui.login.di.a(nVar));
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                this.j = 1;
                obj = I1.b(gVarG, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return (List) obj;
        } catch (Exception e) {
            ((org.slf4j.b) cVar.b).h("Error retrieving users course-instances", e);
            Intrinsics.checkNotNullParameter("Could not get users course instances", "message");
            throw new CourseInstancesException("Could not get users course instances");
        }
    }
}
