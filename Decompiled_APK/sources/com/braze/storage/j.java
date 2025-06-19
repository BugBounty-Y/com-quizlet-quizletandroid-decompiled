package com.braze.storage;

import android.content.SharedPreferences;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.AbstractC1484j;
import com.braze.support.BrazeLogger;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object a;
    public final /* synthetic */ p b;
    public final /* synthetic */ ArrayList c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(p pVar, ArrayList arrayList, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.b = pVar;
        this.c = arrayList;
    }

    public static final String a(String str) {
        return AbstractC1484j.a("Removing card from storage with id: ", str);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        j jVar = new j(this.b, this.c, hVar);
        jVar.a = obj;
        return jVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.a;
        SharedPreferences.Editor editorEdit = this.b.i.edit();
        Iterator it2 = this.c.iterator();
        while (it2.hasNext()) {
            String str = (String) it2.next();
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) c, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new D(str, 1), 7, (Object) null);
            editorEdit.remove(str);
        }
        editorEdit.apply();
        return Unit.a;
    }
}
