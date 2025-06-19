package com.quizlet.shared.cache;

import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_document_scanner.G;
import com.google.android.gms.measurement.internal.J;
import com.mayakapps.kache.C4035d;
import com.mayakapps.kache.InterfaceC4032a;
import java.io.UnsupportedEncodingException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ J k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(J j, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = j;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IllegalAccessException, IllegalArgumentException, UnsupportedEncodingException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        J j = this.k;
        if (i == 0) {
            Z.e(obj);
            C4035d c4035d = (C4035d) j.e;
            if (c4035d != null) {
                return c4035d;
            }
            c cVar = c.b;
            this.j = 1;
            obj = G.a((String) j.c, j.b, cVar, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        j.e = (C4035d) obj;
        return (InterfaceC4032a) obj;
    }
}
