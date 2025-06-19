package com.quizlet.edgy.utils;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3340g;
import com.quizlet.data.repository.studysetwithcreatorinclass.g;
import com.quizlet.edgy.model.AllStates;
import com.quizlet.edgy.model.State;
import com.squareup.moshi.l;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Map;
import kotlin.Unit;
import kotlin.collections.K;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import kotlin.u;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final class c extends i implements Function2 {
    public final /* synthetic */ g j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(g gVar, h hVar) {
        super(2, hVar);
        this.j = gVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new c(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws IOException {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        g gVar = this.j;
        InputStream inputStreamOpen = ((Context) gVar.b).getResources().getAssets().open("allStates.json");
        Intrinsics.checkNotNullExpressionValue(inputStreamOpen, "open(...)");
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStreamOpen, Charsets.UTF_8), 8192);
        try {
            String strB = AbstractC3340g.b(bufferedReader);
            bufferedReader.close();
            Object value = ((u) gVar.f).getValue();
            Intrinsics.checkNotNullExpressionValue(value, "getValue(...)");
            AllStates allStates = (AllStates) ((l) value).b(strB);
            if (allStates == null) {
                return K.a;
            }
            Map map = allStates.a;
            ArrayList arrayList = new ArrayList(map.size());
            for (Map.Entry entry : map.entrySet()) {
                arrayList.add(new State((String) entry.getKey(), (String) entry.getValue()));
            }
            return arrayList;
        } finally {
        }
    }
}
