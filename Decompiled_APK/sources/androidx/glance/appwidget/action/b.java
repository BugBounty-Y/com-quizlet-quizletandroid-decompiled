package androidx.glance.appwidget.action;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3216n7;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.concurrent.CancellationException;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ Intent k;
    public final /* synthetic */ Context l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(Context context, Intent intent, h hVar) {
        super(2, hVar);
        this.k = intent;
        this.l = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.l, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        LinkedHashMap linkedHashMap;
        Intent intent = this.k;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        try {
        } catch (CancellationException e) {
            throw e;
        } catch (Throwable th) {
            Log.e("GlanceAppWidget", "Error in Glance App Widget", th);
        }
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return Unit.a;
        }
        Z.e(obj);
        Bundle extras = intent.getExtras();
        if (extras == null) {
            throw new IllegalArgumentException("The intent must have action parameters extras.");
        }
        Bundle bundle = extras.getBundle("ActionCallbackBroadcastReceiver:parameters");
        if (bundle == null) {
            throw new IllegalArgumentException("The intent must contain a parameters bundle using extra: ActionCallbackBroadcastReceiver:parameters");
        }
        androidx.glance.action.f fVarC = AbstractC3216n7.c(new androidx.glance.action.d[0]);
        Iterator<T> it2 = bundle.keySet().iterator();
        while (true) {
            boolean zHasNext = it2.hasNext();
            linkedHashMap = fVarC.a;
            if (!zHasNext) {
                break;
            }
            String str = (String) it2.next();
            androidx.glance.action.c cVar = new androidx.glance.action.c(str);
            Object obj2 = bundle.get(str);
            linkedHashMap.get(cVar);
            if (obj2 == null) {
                linkedHashMap.remove(cVar);
            } else {
                linkedHashMap.put(cVar, obj2);
            }
        }
        if (extras.containsKey("android.widget.extra.CHECKED")) {
            androidx.glance.action.c cVar2 = g.a;
            Boolean boolValueOf = Boolean.valueOf(extras.getBoolean("android.widget.extra.CHECKED"));
            linkedHashMap.get(cVar2);
            linkedHashMap.put(cVar2, boolValueOf);
        }
        String string = extras.getString("ActionCallbackBroadcastReceiver:callbackClass");
        if (string == null) {
            throw new IllegalArgumentException("The intent must contain a work class name string using extra: ActionCallbackBroadcastReceiver:callbackClass");
        }
        if (!intent.hasExtra("ActionCallbackBroadcastReceiver:appWidgetId")) {
            throw new IllegalArgumentException("To update the widget, the intent must contain the AppWidgetId integer using extra: ActionCallbackBroadcastReceiver:appWidgetId");
        }
        extras.getInt("ActionCallbackBroadcastReceiver:appWidgetId");
        this.j = 1;
        Class<?> cls = Class.forName(string);
        if (!a.class.isAssignableFrom(cls)) {
            throw new IllegalStateException("Provided class must implement ActionCallback.");
        }
        Intrinsics.e(cls.getDeclaredConstructor(null).newInstance(null), "null cannot be cast to non-null type androidx.glance.appwidget.action.ActionCallback");
        throw new ClassCastException();
    }
}
