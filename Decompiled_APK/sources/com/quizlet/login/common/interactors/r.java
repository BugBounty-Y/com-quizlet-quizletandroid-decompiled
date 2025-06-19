package com.quizlet.login.common.interactors;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.ads.C1721Kc;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import java.util.Map;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.V;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class r extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ String k;
    public final /* synthetic */ String l;
    public final /* synthetic */ C1721Kc m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(String str, String str2, C1721Kc c1721Kc, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = str;
        this.l = str2;
        this.m = c1721Kc;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new r(this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((r) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        String str = this.k;
        C1721Kc c1721Kc = this.m;
        try {
            if (i == 0) {
                Z.e(obj);
                Map mapF = V.f(new Pair("username", str), new Pair(DBStudySetFields.Names.PASSWORD, this.l), new Pair("state", ((com.quizlet.qutils.string.c) c1721Kc.c).b()));
                io.reactivex.rxjava3.internal.operators.single.g gVarJ = ((io.ktor.client.plugins.api.d) c1721Kc.b).j((String) mapF.get("username"), mapF);
                this.j = 1;
                obj = I1.b(gVarJ, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return (com.quizlet.login.authentication.data.i) obj;
        } catch (Exception e) {
            return ((io.ktor.client.plugins.api.d) c1721Kc.b).x(str, e);
        }
    }
}
