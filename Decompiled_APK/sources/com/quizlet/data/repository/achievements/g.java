package com.quizlet.data.repository.achievements;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.generated.enums.EnumC4467b;
import com.quizlet.generated.enums.EnumC4491j;
import com.quizlet.remote.model.achievements.AchievementsEvent;
import com.quizlet.remote.service.InterfaceC4774a;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class g extends i implements Function2 {
    public int j;
    public final /* synthetic */ h k;
    public final /* synthetic */ EnumC4491j l;
    public final /* synthetic */ EnumC4467b m;
    public final /* synthetic */ String n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(h hVar, EnumC4491j enumC4491j, EnumC4467b enumC4467b, String str, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.k = hVar;
        this.l = enumC4491j;
        this.m = enumC4467b;
        this.n = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new g(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object obj2 = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        h hVar = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                com.google.android.gms.internal.appset.e eVar = (com.google.android.gms.internal.appset.e) hVar.a;
                EnumC4491j enumC4491j = this.l;
                EnumC4467b enumC4467b = this.m;
                String str = this.n;
                this.j = 1;
                eVar.getClass();
                Object objA = I1.a(((InterfaceC4774a) eVar.b).a(new AchievementsEvent(enumC4491j.a(), enumC4467b.a(), str)), this);
                if (objA != kotlin.coroutines.intrinsics.a.a) {
                    objA = Unit.a;
                }
                if (objA == obj2) {
                    return obj2;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
        } catch (Exception e) {
            ((org.slf4j.b) hVar.b).m("Remote error trying to post Achievements event as shown: " + e.getMessage());
        }
        return Unit.a;
    }
}
