package com.braze.storage;

import android.content.SharedPreferences;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ p a;
    public final /* synthetic */ JSONObject b;
    public final /* synthetic */ String c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(p pVar, JSONObject jSONObject, String str, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = pVar;
        this.b = jSONObject;
        this.c = str;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.a, this.b, this.c, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        SharedPreferences.Editor editorEdit = this.a.i.edit();
        JSONObject jSONObject = this.b;
        if (jSONObject != null) {
            editorEdit.putString(this.c, jSONObject.toString());
        } else {
            editorEdit.remove(this.c);
        }
        editorEdit.apply();
        return Unit.a;
    }
}
