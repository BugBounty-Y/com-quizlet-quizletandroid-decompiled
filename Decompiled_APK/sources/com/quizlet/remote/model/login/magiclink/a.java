package com.quizlet.remote.model.login.magiclink;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.I1;
import com.quizlet.data.model.G1;
import com.quizlet.remote.model.login.magiclink.SendMagicLinkResponse;
import io.reactivex.rxjava3.core.p;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.collections.U;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ b k;
    public final /* synthetic */ String l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(b bVar, String str, h hVar) {
        super(2, hVar);
        this.k = bVar;
        this.l = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        b bVar = this.k;
        try {
            if (i == 0) {
                Z.e(obj);
                p<SendMagicLinkResponse> pVarE = bVar.a.e(U.b(new Pair("email", this.l)));
                this.j = 1;
                obj = I1.b(pVarE, this);
                if (obj == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            Intrinsics.checkNotNullExpressionValue(obj, "await(...)");
            SendMagicLinkResponse sendMagicLinkResponse = (SendMagicLinkResponse) obj;
            if (sendMagicLinkResponse.a) {
                return G1.a;
            }
            SendMagicLinkResponse.Errors errors = sendMagicLinkResponse.b;
            if ((errors != null ? errors.a : null) != null) {
                return G1.b;
            }
            return (errors != null ? errors.b : null) != null ? G1.c : G1.d;
        } catch (Throwable unused) {
            return G1.d;
        }
    }
}
