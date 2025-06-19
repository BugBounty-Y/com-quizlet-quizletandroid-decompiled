package com.quizlet.security.qltj.core;

import androidx.glance.appwidget.protobuf.Z;
import androidx.recyclerview.widget.C1372j;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3335e2;
import com.quizlet.local.datastore.preferences.B;
import com.quizlet.local.datastore.preferences.J;
import java.util.regex.Pattern;
import kotlin.Unit;
import kotlin.collections.A;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import okhttp3.C5083l;
import okhttp3.n;
import okhttp3.s;

/* loaded from: classes3.dex */
public final class a extends i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.remote.model.union.folderwithcreator.b k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.remote.model.union.folderwithcreator.b bVar, h hVar) {
        super(2, hVar);
        this.k = bVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new a(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((a) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.remote.model.union.folderwithcreator.b bVar = this.k;
        if (i == 0) {
            Z.e(obj);
            J j = (J) bVar.b;
            this.j = 1;
            obj = j.b(this);
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
        if (b != null) {
            String str = b.b;
            Intrinsics.checkNotNullParameter(str, "<this>");
            C1372j c1372j = new C1372j();
            c1372j.l(null, str);
            s sVarD = c1372j.d();
            Pattern pattern = C5083l.j;
            C5083l c5083lL = AbstractC3335e2.l(sVarD, b.a);
            if (c5083lL != null) {
                ((n) bVar.a).a(sVarD, A.b(c5083lL));
            }
        }
        return Unit.a;
    }
}
