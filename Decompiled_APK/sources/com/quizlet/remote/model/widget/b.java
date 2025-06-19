package com.quizlet.remote.model.widget;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.ads.internal.client.C1608n;
import com.quizlet.data.model.y2;
import com.quizlet.data.model.z2;
import com.quizlet.remote.service.F;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import retrofit2.HttpException;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ C1608n k;
    public final /* synthetic */ int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(C1608n c1608n, int i, h hVar) {
        super(2, hVar);
        this.k = c1608n;
        this.l = i;
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
        C1608n c1608n = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                F f = (F) c1608n.a;
                int i2 = this.l;
                this.j = 1;
                obj = f.a(i2, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            Object obj2 = c1608n.b;
            return a.a((SuggestedSetsResponse) obj);
        } catch (HttpException e) {
            ((org.slf4j.b) c1608n.e).m("Remote error trying to get widget suggested-sets: " + e.getMessage());
            return e.a == 403 ? z2.a : y2.a;
        }
    }
}
