package com.perimeterx.mobile_sdk.requests_interceptor;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.L4;
import com.perimeterx.mobile_sdk.block.b;
import com.perimeterx.mobile_sdk.session.d;
import com.perimeterx.mobile_sdk.session.l;
import java.net.URL;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.J;
import kotlinx.coroutines.C;
import okhttp3.s;

/* loaded from: classes2.dex */
public final class a extends i implements Function2 {
    public J j;
    public int k;
    public final /* synthetic */ J l;
    public final /* synthetic */ s m;
    public final /* synthetic */ b n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(J j, s sVar, b bVar, h hVar) {
        super(2, hVar);
        this.l = j;
        this.m = sVar;
        this.n = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        J j;
        Boolean bool;
        J j2;
        d dVarA;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        if (i == 0) {
            Z.e(obj);
            l lVar = L4.b;
            j = this.l;
            if (lVar == null) {
                bool = null;
                j.a = bool;
                return Unit.a;
            }
            URL urlK = this.m.k();
            this.j = j;
            this.k = 1;
            b bVar = this.n;
            String str = bVar.b;
            if (str == null || (dVarA = l.a(str)) == null) {
                d dVarB = l.b(urlK, com.perimeterx.mobile_sdk.business_logic.b.a);
                obj = dVarB != null ? dVarB.c(bVar, urlK.toString(), this) : Boolean.FALSE;
            } else {
                obj = dVarA.c(bVar, urlK.toString(), this);
            }
            if (obj == aVar) {
                return aVar;
            }
            j2 = j;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            j2 = this.j;
            Z.e(obj);
        }
        bool = (Boolean) obj;
        j = j2;
        j.a = bool;
        return Unit.a;
    }
}
