package com.quizlet.quizletandroid.ui.studymodes.match.viewmodel;

import android.content.SharedPreferences;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.match.data.C4348d;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public final /* synthetic */ g j;
    public final /* synthetic */ long k;
    public final /* synthetic */ long l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(g gVar, long j, long j2, h hVar) {
        super(2, hVar);
        this.j = gVar;
        this.k = j;
        this.l = j2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new d(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        g gVar = this.j;
        gVar.l.n();
        C4348d c4348d = new C4348d(this.k, this.l);
        gVar.m.j(c4348d);
        com.quizlet.ads.d dVar = gVar.h.j;
        if (dVar != null) {
            StringBuilder sb = new StringBuilder("RateUsPromoSessionCount_");
            long j = dVar.a;
            sb.append(j);
            String string = sb.toString();
            SharedPreferences sharedPreferences = dVar.b;
            int i = sharedPreferences.getInt(string, 0) + 1;
            if (i <= 3) {
                sharedPreferences.edit().putInt("RateUsPromoSessionCount_" + j, i).apply();
            }
        }
        gVar.B(c4348d);
        return Unit.a;
    }
}
